use kernel::prelude::*;
use kernel::bindings::*;
use kernel::c_types::*;
use kernel::Error;
use kernel::yama_rust_interfaces::*;
use kernel::{define_lsm, count};
use core::convert::TryInto;
use core::ptr::null_mut;
use kernel::sync::*;
use kernel::spinlock_init;
use kernel::linked_list::*;
use core::cell::UnsafeCell;

// LSM name - serves as a unique identifier for this security module
const __NAME: &[u8] = b"test_rust_lsm\0";
// log prefix required for pr_info
const __LOG_PREFIX: &[u8] = __NAME;

const YAMA_RUST_SCOPE_DISABLED: c_int = 0;
const YAMA_RUST_SCOPE_RELATIONAL: c_int = 1;
const YAMA_RUST_SCOPE_CAPABILITY: c_int = 2;
const YAMA_RUST_SCOPE_NO_ATTACH: c_int = 3;

static mut PTRACE_SCOPE: c_int = YAMA_RUST_SCOPE_RELATIONAL;

#[derive(Clone)]
enum PtraceRelation {
    AnyTracer { tracee: TaskStructRef },
    TracerTracee { tracer: TaskStructRef, tracee: TaskStructRef },
}

impl PtraceRelation {
    fn get_tracee(&self) -> TaskStructRef {
        match self {
            PtraceRelation::AnyTracer { tracee } => {
                tracee.clone()
            },
            PtraceRelation::TracerTracee { tracer, tracee } => {
                tracee.clone()
            }
        }
    }
}

struct PtraceRelationNode {
    relation: PtraceRelation,
    rcu_head: callback_head,
    pub(crate) invalid: bool,
    links: RCULinks<PtraceRelationNode>,
}

impl PtraceRelationNode {
    pub(crate) fn new(relation: PtraceRelation, invalid: bool) -> PtraceRelationNode {
        
        return PtraceRelationNode {
            relation,
            rcu_head: callback_head {
                next: core::ptr::null_mut(),
                func: None,
            },
            invalid,
            links: RCULinks::new(),
        }
    }
}

impl GetRCUHead for PtraceRelationNode {
    fn get_rcu_head(&self) -> *mut callback_head {
        &self.rcu_head as *const _ as *mut _
    }
}

impl RCUGetLinks for PtraceRelationNode {

    type EntryType = PtraceRelationNode;

    fn get_links(data: &mut Self::EntryType) -> &mut RCULinks<Self::EntryType> {
        &mut data.links
    }

}

static ptracer_relations: PtraceRelationListOuter = PtraceRelationListOuter::new();

struct PtraceRelationListOuter {
    list: UnsafeCell<PtraceRelationList>
}

unsafe impl Sync for PtraceRelationListOuter { }

impl PtraceRelationListOuter {
    pub(crate) const fn new() -> PtraceRelationListOuter {
        PtraceRelationListOuter { 
            list: UnsafeCell::new(PtraceRelationList::Uninitialized), 
        }
    }

    // must not be run concurrently with any other methods
    #[link_section = ".init.text"]
    pub(crate) unsafe fn init(&self) {
        let r = unsafe { &mut *self.list.get() };

        if let PtraceRelationList::Uninitialized = r {
            *r = PtraceRelationList::new_init();
        }
    }

    pub(crate) fn if_initialized<R, F: FnOnce(&PtraceRelationListInner) -> R>(&self, f: F) -> Result<R> {
        // safe assuming init cannot be called concurrently
        let list = unsafe { &*self.list.get() };
        if let PtraceRelationList::Initialized { inner } = list {
            Ok(f(inner))
        } else {
            Err(Error::EINVAL)
        }
    }

    pub(crate) fn cleanup_relations(&self) {
        self.if_initialized(|inner| {
            inner.cleanup_relations();
        }).unwrap();
    }

    pub(crate) fn add_relation(&self, relation: PtraceRelation) {
        self.if_initialized(|inner| {
            inner.add_relation(relation);
        }).unwrap();
    }

    pub(crate) fn del_relation(&self, tracer_task: Option<TaskStructRef>, tracee_task: Option<TaskStructRef>) {
        self.if_initialized(|inner| {
            inner.del_relation(tracer_task, tracee_task);
        }).unwrap();
    }
    
    pub(crate) fn exception_found(&self, tracer_task: TaskStructRef, tracee_task: TaskStructRef) -> bool {
        self.if_initialized(|inner| {
            inner.exception_found(tracer_task, tracee_task)
        }).unwrap()
    }
}

enum PtraceRelationList {
    Initialized { inner: PtraceRelationListInner },
    Uninitialized,
}

impl PtraceRelationList {
    pub(crate) fn new_init() -> PtraceRelationList {
        let mut list = PtraceRelationList::Initialized {
            inner: PtraceRelationListInner {
                list: UnsafeCell::new(RCUList::new()),
                lock: Pin::from(Box::try_new(unsafe { SpinLock::new(()) }).unwrap()),
            }
        };
        if let PtraceRelationList::Initialized { ref mut inner } = list {
            spinlock_init!(inner.lock.as_mut(), "a::b::C");
        }
        list
    }
}

struct PtraceRelationListInner {
    // list
    list: UnsafeCell<RCUList<PtraceRelationNode>>,
    // spinlock synchronizing write access to list
    lock: Pin<Box<SpinLock<()>>>,
}

impl PtraceRelationListInner {

    pub(crate) fn cleanup_relations(&self) {
        // lock spinlock to synchronize mutable access to list
        let lock = (*self.lock).lock();
        // get reference to list: safe as lock is held
        let list = unsafe {
            &mut *self.list.get()
        };
        // enter RCU critical section
        with_rcu_read_lock(|ctx| {
            // get a write-enabled cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_mut_rcu(ctx);
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation) = cursor.current() {
                // check if the relation is invalid and remove if so
                if relation.invalid {
                    // this returns a Box, meaning the underlying element is deallocated
                    // once the Box goes out of scope
                    pr_info!("Removing invalid relationship!\n");
                    cursor.remove_current_rcu(ctx)
                } else {
                    cursor.move_next_rcu(ctx);
                }
            }
        });
    }

    pub(crate) fn add_relation(&self, relation: PtraceRelation) {
        // lock spinlock to synchronize mutable access to list
        let lock = (*self.lock).lock();
        // get reference to list: safe as lock is held
        let list = unsafe {
            &mut *self.list.get()
        };
        // allocate memory for new item
        let new_item = Box::try_new(PtraceRelationNode::new(relation.clone(), false)).unwrap();
        // enter RCU critical section
        with_rcu_read_lock(|ctx| {
            // get a cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_mut_rcu(ctx);
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation_node) = cursor.current() {
                if !relation_node.invalid {
                    // update tracer if an existing relationship is present
                    if relation_node.relation.get_tracee() == relation.get_tracee() {
                        pr_info!("Replacing relationship!\n");
                        cursor.replace_current_rcu(new_item, ctx);
                        return;
                    }
                }
                cursor.move_next_rcu(ctx);
            }
            pr_info!("Adding new relationship!\n");
            // if an existing relationship wasn't found, add a new one
            list.push_back_rcu(new_item, ctx);
        });
    }

    pub(crate) fn del_relation(&self, tracer_task: Option<TaskStructRef>, tracee_task: Option<TaskStructRef>) {
        // get reference to list: safe as accesses are safe
        // even with concurrent mutable access to list
        let list = unsafe {
            &mut *self.list.get()
        };
        // enter RCU critical section
        with_rcu_read_lock(|ctx| {
            // get a cursor pointing to the first element of the list,
            // safe as write accesses (setting invalid) are safe - 
            // worst case invalid is set for an old item
            // which is then removed
            let mut cursor = list.cursor_front_inplace_mut_rcu(ctx);
            // let mut count = 0;
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation_node_ptr) = cursor.current_mut() {
                // count = count + 1;
                // SAFETY: read access
                if unsafe { !(*relation_node_ptr).invalid } {
                    if let Some(t) = &tracer_task {
                        // SAFETY: read access
                        if let PtraceRelation::TracerTracee { tracer, tracee } = unsafe { &(*relation_node_ptr).relation } {
                            if *t == *tracer {
                                pr_info!("Found match, marking relationship as invalid!\n");
                                // SAFETY: updating invalid is safe, see above
                                unsafe {
                                    (*relation_node_ptr).invalid = true;
                                }
                            }
                        }
                    }
                    // obs - help consider borrowing here - move during loop
                    if let Some(t) = &tracee_task {
                        // SFAETY: read access
                        if *t == unsafe { (*relation_node_ptr).relation.get_tracee() } {
                            pr_info!("Found match, marking relationship as invalid!\n");
                            // SAFETY: updating invalid is safe, see above
                            unsafe { 
                                (*relation_node_ptr).invalid = true;
                            }
                        }
                    }
                }
                cursor.move_next_rcu(ctx);
            }
            // pr_info!("Relationships: {}\n", count);
        });

        self.cleanup_relations();
    }

    pub(crate) fn exception_found(&self, tracer_task: TaskStructRef, tracee_task: TaskStructRef) -> bool {
        with_rcu_read_lock(|ctx| {
            let mut found = false;
            let mut tracee_task = tracee_task;
            let mut parent = tracee_task.get_ptrace_parent(ctx).unwrap();
            if !parent.null() && parent.same_thread_group(&tracer_task) {
                pr_info!("Parent: {}, tracer: {}\n", parent.pid(), parent.pid());
                pr_info!("Existing trace relationship!\n");
                return true;
            }
    
            tracee_task = tracee_task.get_thread_group_leader(ctx).unwrap();
    
            // obs - more elegant than bool, null pointer
            let mut relation: Option<PtraceRelation> = None;
    
            // get reference to list: safe as accesses will be read only RCU
            let list = unsafe {
                &mut *self.list.get()
            };

            // get a cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_rcu(ctx);
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation_node) = cursor.current() {
                if !relation_node.invalid {
                    if relation_node.relation.get_tracee() == tracee_task {
                        relation = Some(relation_node.relation.clone());
                        break;
                    }
                }
                cursor.move_next_rcu(ctx);
            }
    
            if let Some(r) = relation {
                match r {
                    PtraceRelation::AnyTracer { tracee } => {
                        return true;
                    },
                    PtraceRelation::TracerTracee { tracer, tracee } => {
                        if task_is_descendant(tracer, tracer_task) {
                            return true;
                        }
                    }
                }
            }
    
            return false;
        })
    }
}

fn task_is_descendant(parent: TaskStructRef, child: TaskStructRef) -> bool {

    let mut ret = false;

    with_rcu_read_lock(|ctx| {

        let mut parent = parent.get_thread_group_leader(ctx).unwrap();
        let mut walker = child;

        while walker.pid() > 0 {
            walker = walker.get_thread_group_leader(ctx).unwrap();
            if walker == parent {
                ret = true;
                break;
            }
            walker = walker.get_real_parent(ctx).unwrap();
        }
    });
    
    ret
}

struct TestRustLSM;

impl SecurityHooks for TestRustLSM {

    fn ptrace_access_check(child: TaskStructRef, mode: c_uint) -> Result {

        pr_info!("Ptrace access check!\n");

        let mut ret = Ok(());

        if (mode & PTRACE_MODE_ATTACH) != 0 {

            pr_info!("Ptrace attach!\n");

            match unsafe { PTRACE_SCOPE } {
                YAMA_RUST_SCOPE_DISABLED => {
                    ret = Ok(());
                },
                YAMA_RUST_SCOPE_RELATIONAL => {
                    ret = with_rcu_read_lock(|ctx| {
                        let child_alive = child.pid_alive();
                        let is_descendant =
                            task_is_descendant(TaskStructRef::current().unwrap(), child.clone());
                        let exception_found = 
                            ptracer_relations.exception_found(TaskStructRef::current().unwrap(), child.clone());
                        let has_capability = child.user_ns_capable(CAP_SYS_PTRACE, ctx);
                        pr_info!("Alive: {}, Capability: {}, Is Descendant: {}, Exception: {}\n", child_alive, has_capability, is_descendant, exception_found);
                        if child_alive && !is_descendant && !exception_found && !has_capability {
                            pr_info!("Denied!\n");
                            Err(Error::EPERM)
                        } else {
                            Ok(())
                        }
                    });
                },
                YAMA_RUST_SCOPE_CAPABILITY => {
                    ret = with_rcu_read_lock(|ctx| {
                        let has_capability = child.user_ns_capable(CAP_SYS_PTRACE, ctx);
                        if !has_capability {
                            pr_info!("Denied!\n");
                            Err(Error::EPERM)
                        } else {
                            Ok(())
                        }
                    });
                },
                YAMA_RUST_SCOPE_NO_ATTACH => {
                    pr_info!("Denied!\n");
                    ret = Err(Error::EPERM);
                },
                _ => {
                    pr_info!("Denied!\n");
                    ret = Err(Error::EPERM);
                }
            }
        }

        return ret;
    }

    fn ptrace_traceme(parent: TaskStructRef) -> Result {

        let mut ret = Ok(());

        if unsafe { PTRACE_SCOPE } == YAMA_RUST_SCOPE_CAPABILITY {
            let has_capability = unsafe {
                has_ns_capability(parent.get_ptr().as_ptr(), current_user_ns_exported(), CAP_SYS_PTRACE.try_into().unwrap())
            };
            if !has_capability {
                ret = Err(Error::EPERM);
                pr_info!("Traceme denied!\n");
            }
        } else if unsafe { PTRACE_SCOPE } == YAMA_RUST_SCOPE_NO_ATTACH {
            pr_info!("Traceme denied!\n");
            ret = Err(Error::EPERM);
        } else {
            pr_info!("Traceme permitted!\n");
        }

        return ret;
    }

    fn task_free(task: TaskStructRef) {
        ptracer_relations.del_relation(Some(task.clone()), Some(task.clone()));
    }

    fn task_prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> Result {
        
        let mut ret = Err(Error::ENOSYS);

        if option == PR_SET_PTRACER as c_int {

            let mut myself = with_rcu_read_lock(|ctx| {
                TaskStructRef::current_get().unwrap().get_thread_group_leader(ctx).unwrap()
            });

            // no tracing permitted
            if arg2 == 0 {
                pr_info!("Removing tracee relationship!\n");
                ptracer_relations.del_relation(None, Some(myself));
                ret = Ok(());
            } else if arg2 as i32 == -1 {
                pr_info!("Adding tracee relationship: any tracer!\n");
                ptracer_relations.add_relation(PtraceRelation::AnyTracer {
                    tracee: myself,
                });
            } else {
                pr_info!("Adding tracee relationship!\n");
                let tracer = unsafe {
                    find_get_task_by_vpid(arg2 as pid_t)
                };
                if tracer == null_mut() {
                    ret = Err(Error::EINVAL);
                } else {
                    let tracer = unsafe {
                        TaskStructRef::from_ptr(tracer).unwrap()
                    };
                    ptracer_relations.add_relation(PtraceRelation::TracerTracee {
                        tracer: tracer,
                        tracee: myself,
                    });
                    ret = Ok(());
                }
            }
        }
        
        return ret;
    }
}

impl SecurityModule for TestRustLSM {
    #[link_section = ".init.text"]
    fn init(hooks: &mut SecurityHookList) -> Result {
        pr_info!("Successfully initialized simple Rust LSM!\n");

        // SAFETY: no other methods will be getting called as
        // hooks are not yet registered
        unsafe {
            ptracer_relations.init();
        }

        // SAFETY: register is being called during init, 
        // and there is no other access to hooks array
        let ret = unsafe { hooks.register() };
        match ret {
            Ok(_) => {
                pr_info!("Hooks registered successfully!\n");
                return Ok(());
            },
            Err(e) => {
                pr_info!("Error registering hooks: {}\n", e.to_kernel_errno());
                return Err(e);
            }
        }
    }
}

define_lsm!(
    "test_rust_lsm",
    TestRustLSM,
    ptrace_access_check, ptrace_traceme, task_free, task_prctl
);
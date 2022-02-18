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
use core::cell::RefCell;

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
        unsafe {
            &self.rcu_head as *const _ as *mut _
        }
    }
}

impl RCUGetLinks for PtraceRelationNode {

    type EntryType = PtraceRelationNode;

    fn get_links(data: &mut Self::EntryType) -> &mut RCULinks<Self::EntryType> {
        &mut data.links
    }

}

type PtraceRelationList = RCUList<PtraceRelationNode>;
type PtraceRelationListContainer = Pin<Box<SpinLock<PtraceRelationList>>>;

static mut ptracer_relations: Option<PtraceRelationListContainer> = None;

fn yama_relation_cleanup() {
    // mutably borrow spinlock-protected list if present
    if let Some(ref mut p) = unsafe { &mut ptracer_relations } {
        // lock spinlock to mutably borrow the inner list
        let list = &mut *p.lock();
        with_rcu_read_lock(|| {
            // get a cursor pointing to the first element of the list
            let mut cursor = unsafe {
                list.cursor_front_mut_rcu()
            };
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation) = cursor.current() {
                // check if the relation is invalid and remove if so
                if relation.invalid {
                    // this returns a Box, meaning the underlying element is deallocated
                    // once the Box goes out of scope
                    pr_info!("Removing invalid relationship!\n");
                    unsafe {
                        cursor.remove_current_rcu()
                    }
                } else {
                    unsafe {
                        cursor.move_next_rcu();
                    }
                }
            }
        });
    }
}

fn yama_ptracer_add(relation: PtraceRelation) {
    // mutably borrow spinlock-protected list if present
    if let Some(ref mut p) = unsafe { &mut ptracer_relations } {
        
        // allocate memory for new item
        let new_item = Box::try_new(PtraceRelationNode::new(relation.clone(), false)).unwrap();
        
        // lock spinlock to mutably borrow the inner list
        let list = &mut *p.lock();

        with_rcu_read_lock(|| {
            // get a cursor pointing to the first element of the list
            let mut cursor = unsafe {
                list.cursor_front_mut_rcu()
            };
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation_node) = cursor.current() {
                if !relation_node.invalid {
                    // update tracer if an existing relationship is present
                    if relation_node.relation.get_tracee() == relation.get_tracee() {
                        pr_info!("Replacing relationship!\n");
                        unsafe {
                            cursor.replace_current_rcu(new_item);
                        }
                        return;
                    }
                }
                unsafe {
                    cursor.move_next_rcu();
                }
            }
            pr_info!("Adding new relationship!\n");
            // if an existing relationship wasn't found, add a new one
            list.push_back(new_item);
        });
    }
}

fn yama_ptracer_del(tracer_task: Option<TaskStructRef>, tracee_task: Option<TaskStructRef>) {
    // mutably borrow spinlock-protected list if present
    if let Some(ref mut p) = unsafe { &mut ptracer_relations } {
        // lock spinlock to mutably borrow the inner list
        let list = &mut *p.lock();
        
        with_rcu_read_lock(|| {
            // get a cursor pointing to the first element of the list
            let mut cursor = unsafe {
                list.cursor_front_mut_rcu()
            };
            // let mut count = 0;
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation_node) = cursor.current() {
                // count = count + 1;
                if !relation_node.invalid {
                    // obs - help consider borrowing here - move during loop
                    if let Some(t) = &tracer_task {
                        // obs - help consider borrowing here
                        if let PtraceRelation::TracerTracee { tracer, tracee } = &relation_node.relation {
                            if *t == *tracer {
                                pr_info!("Found match, marking relationship as invalid!\n");
                                relation_node.invalid = true;
                            }
                        }
                    }
                    // obs - help consider borrowing here - move during loop
                    if let Some(t) = &tracee_task {
                        if *t == relation_node.relation.get_tracee() {
                            pr_info!("Found match, marking relationship as invalid!\n");
                            relation_node.invalid = true;
                        }
                    }
                }
                unsafe {
                    cursor.move_next_rcu();
                }
            }
            // pr_info!("Relationships: {}\n", count);
        });
    }

    yama_relation_cleanup();
}

fn task_is_descendant(parent: TaskStructRef, child: TaskStructRef) -> bool {

    let mut ret = false;

    with_rcu_read_lock(|| {

        let mut parent = unsafe {
            parent.get_thread_group_leader().unwrap()
        };
        let mut walker = child;

        while walker.pid() > 0 {
            walker = unsafe {
                walker.get_thread_group_leader().unwrap()
            };
            if walker == parent {
                ret = true;
                break;
            }
            walker = unsafe {
                walker.get_real_parent().unwrap()
            };
        }
    });
    
    ret
}

fn ptracer_exception_found(tracer_task: TaskStructRef, tracee_task: TaskStructRef) -> bool {
    with_rcu_read_lock(|| {
        let mut found = false;
        let mut tracee_task = tracee_task;
        let mut parent = unsafe {
            tracee_task.get_ptrace_parent().unwrap()
        };
        if !parent.null() && parent.same_thread_group(&tracer_task) {
            pr_info!("Parent: {}, tracer: {}\n", parent.pid(), parent.pid());
            pr_info!("Existing trace relationship!\n");
            return true;
        }

        tracee_task = unsafe { 
            tracee_task.get_thread_group_leader().unwrap()
        };

        // obs - more elegant than bool, null pointer
        let mut relation: Option<PtraceRelation> = None;

        // mutably borrow spinlock-protected list if present
        if let Some(ref mut p) = unsafe { &mut ptracer_relations } {
            // lock spinlock to mutably borrow the inner list
            let list = &mut *p.lock();

            with_rcu_read_lock(|| {
                // get a cursor pointing to the first element of the list
                let mut cursor = unsafe {
                    list.cursor_front_mut_rcu()
                };
                // unwrap each element of the list in turn, moving the cursor along
                while let Some(relation_node) = cursor.current() {
                    if !relation_node.invalid {
                        if relation_node.relation.get_tracee() == tracee_task {
                            relation = Some(relation_node.relation.clone());
                            break;
                        }
                    }
                    unsafe {
                        cursor.move_next_rcu();
                    }
                }
            });
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
                    ret = with_rcu_read_lock(|| {
                        let child_alive = child.pid_alive();
                        let is_descendant =
                            task_is_descendant(TaskStructRef::current().unwrap(), child.clone());
                        let exception_found = 
                            ptracer_exception_found(TaskStructRef::current().unwrap(), child.clone());
                        let has_capability = unsafe {
                            child.user_ns_capable(CAP_SYS_PTRACE)
                        };
                        pr_info!("Alive: {}, Capability: {}, Is Descendant: {}, Exception: {}\n", child_alive, has_capability, is_descendant, exception_found);
                        if child_alive && !is_descendant && !exception_found && !has_capability {
                            pr_info!("Denied!\n");
                            Err(Error::EPERM)
                        } else {
                            Ok(())
                        }
                    })
                },
                YAMA_RUST_SCOPE_CAPABILITY => {
                    ret = with_rcu_read_lock(|| {
                        let has_capability = unsafe {
                            child.user_ns_capable(CAP_SYS_PTRACE)
                        };
                        if !has_capability {
                            pr_info!("Denied!\n");
                            Err(Error::EPERM)
                        } else {
                            Ok(())
                        }
                    })
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
        yama_ptracer_del(Some(task.clone()), Some(task.clone()));
    }

    fn task_prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> Result {
        
        let mut ret = Err(Error::ENOSYS);

        if option == PR_SET_PTRACER as c_int {

            let mut myself = with_rcu_read_lock(|| {
                unsafe {
                    TaskStructRef::current_get().unwrap().get_thread_group_leader().unwrap()
                }
            });

            // no tracing permitted
            if arg2 == 0 {
                pr_info!("Removing tracee relationship!\n");
                yama_ptracer_del(None, Some(myself));
                ret = Ok(());
            } else if arg2 as i32 == -1 {
                pr_info!("Adding tracee relationship: any tracer!\n");
                yama_ptracer_add(PtraceRelation::AnyTracer {
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
                    yama_ptracer_add(PtraceRelation::TracerTracee {
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

        // initialize the global, spinlock-protected list of ptracer relations
        // SAFETY: this should be the only place the variable itself is mutated
        // and nothing else will be accessing it as no hooks have been registered
        unsafe {
            ptracer_relations = Some(Pin::from(Box::try_new(SpinLock::new(RCUList::new()))?));
            if let Some(ref mut p) = &mut ptracer_relations {
                let a = &mut *p.lock();
                // pr_info!("Empty: {}\n", a.is_empty());
            }
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
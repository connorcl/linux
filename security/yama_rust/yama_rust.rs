use kernel::prelude::*;
use kernel::bindings::*;
use kernel::c_types::*;
use kernel::Error;
use kernel::yama_rust_interfaces::*;
use kernel::{define_lsm, count, init_static_sync};
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

static PTRACE_SCOPE: c_int = YAMA_RUST_SCOPE_CAPABILITY;

struct PtraceRelation {
    pub(crate) tracer: *mut task_struct,
    pub(crate) tracee: *mut task_struct,
    pub(crate) invalid: bool,
    links: Links<PtraceRelation>,
}

impl PtraceRelation {
    pub(crate) fn new(tracer: *mut task_struct, tracee: *mut task_struct, invalid: bool) -> PtraceRelation {
        return PtraceRelation {
            tracer,
            tracee,
            invalid,
            links: Links::new(),
        }
    }
}

impl GetLinks for PtraceRelation {
    type EntryType = PtraceRelation;

    fn get_links(data: &Self::EntryType) -> &Links<Self::EntryType> {
        return &data.links;
    }
}

type PtraceRelationList = List<Box<PtraceRelation>>;
// type PtraceRelationListContainer = Pin<Box<SpinLock<PtraceRelationList>>>;

struct PtraceRelationListWrapper(PtraceRelationList);

unsafe impl Send for PtraceRelationListWrapper { }

init_static_sync! {
    static PTRACE_RELATIONS: SpinLock<PtraceRelationListWrapper> = PtraceRelationListWrapper(PtraceRelationList::new());
}

// static mut ptracer_relations: Option<PtraceRelationListContainer> = None;

unsafe fn yama_relation_cleanup() {
    unsafe {
        // mutably borrow spinlock-protected list if present
        // if let Some(ref mut p) = &mut ptracer_relations {
            // lock spinlock to mutably borrow the inner list
            let list = &mut PTRACE_RELATIONS.lock().0;
            // get a cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_mut();
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation) = cursor.current() {
                // check if the relation is invalid and remove if so
                if relation.invalid {
                    // this returns a Box, meaning the underlying element is deallocated
                    // once the Box goes out of scope
                    pr_info!("Removing invalid relationship!\n");
                    cursor.remove_current();
                } else {
                    cursor.move_next();
                }
            }
        // }
    }
}

unsafe fn yama_ptracer_add(tracer: *mut task_struct, tracee: *mut task_struct) {    
    unsafe {
        // mutably borrow spinlock-protected list if present
        // if let Some(ref mut p) = &mut ptracer_relations {
            // lock spinlock to mutably borrow the inner list
            let list = &mut PTRACE_RELATIONS.lock().0;
            // get a cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_mut();
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation) = cursor.current() {
                if !relation.invalid {
                    // update tracer if an existing relationship is present
                    if relation.tracee == tracee {
                        pr_info!("Updating relationship!\n");
                        relation.tracer = tracer;
                        return;
                    }
                }
                cursor.move_next();
            }
            pr_info!("Adding new relationship!\n");
            // if an existing relationship wasn't found, add a new one
            list.push_back(Box::try_new(PtraceRelation::new(tracer, tracee, false)).unwrap());
        // }
    }
}

unsafe fn yama_ptracer_del(tracer: *mut task_struct, tracee: *mut task_struct) {
    unsafe {
        // mutably borrow spinlock-protected list if present
        // if let Some(ref mut p) = &mut ptracer_relations {
            // lock spinlock to mutably borrow the inner list
            let list = &mut PTRACE_RELATIONS.lock().0;
            // get a cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_mut();
            let mut count = 0;
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation) = cursor.current() {
                count = count + 1;
                if !relation.invalid {
                    if relation.tracee == tracee || 
                        (tracer != null_mut() && relation.tracer == tracer) {
                        pr_info!("Found match, marking relationship as invalid!\n");
                        relation.invalid = true;
                    }
                }
                cursor.move_next();
            }
            pr_info!("Relationships: {}\n", count);
        // }

        yama_relation_cleanup();
    }
}

unsafe fn pid_alive(task: *mut task_struct) -> bool {
    unsafe {
        (*task).thread_pid != null_mut()
    }
}

unsafe fn thread_group_leader(task: *mut task_struct) -> bool {
    unsafe {
        (*task).exit_signal >= 0
    }
}

unsafe fn task_is_descendant(mut parent: *mut task_struct, child: *mut task_struct) -> bool {
    unsafe {
        if parent == null_mut() || child == null_mut() {
            return false;
        }

        let mut ret = false;
        let mut walker: *mut task_struct = child;

        rcu_read_lock_exported();

        if !thread_group_leader(parent) {
            parent = rcu_dereference_exported(&mut (*parent).group_leader as *mut *mut _ as *mut *mut c_void) as *mut task_struct;
        }

        while (*walker).pid > 0 {
            if !thread_group_leader(walker) {
                walker = rcu_dereference_exported(&mut (*walker).group_leader as *mut *mut _ as *mut *mut c_void) as *mut task_struct;
            }
            if walker == parent {
                ret = true;
                break;
            }
            walker = rcu_dereference_exported(&mut (*walker).real_parent as *mut *mut _ as *mut *mut c_void) as *mut task_struct;
        }        

        rcu_read_unlock_exported();
        
        ret
    }
}

unsafe fn ptracer_exception_found(tracer: *mut task_struct, mut tracee: *mut task_struct) -> bool {
    unsafe {

        let mut found = false;

        rcu_read_lock_exported();

        let mut parent = ptrace_parent_exported(tracee);
        if parent != null_mut() && same_thread_group_exported(parent, tracer) {
            pr_info!("Parent: {}, tracer: {}\n", (*parent).pid, (*tracer).pid);
            rcu_read_unlock_exported();
            pr_info!("Existing trace relationship!\n");
            return true;
        }

        if !thread_group_leader(tracee) {
            tracee = rcu_dereference_exported(&mut (*tracee).group_leader as *mut *mut _ as *mut *mut c_void) as *mut task_struct;
        }

        // mutably borrow spinlock-protected list if present
        // if let Some(ref mut p) = &mut ptracer_relations {
            // lock spinlock to mutably borrow the inner list
            let list = &mut PTRACE_RELATIONS.lock().0;
            // get a cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_mut();
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation) = cursor.current() {
                if !relation.invalid {
                    if relation.tracee == tracee {
                        parent = relation.tracer;
                        found = true;
                        break;
                    }   
                }
                cursor.move_next();
            }
        // }

        if found && (parent == null_mut() || task_is_descendant(parent, tracer)) {
            rcu_read_unlock_exported();
            return true;
        }

        return false;
    }
}

struct TestRustLSM;

impl SecurityHooks for TestRustLSM {

    // fn bprm_check_security() -> Result {
    //     pr_info!("BPRM hook method executed successfully!\n");
    //     return Ok(());
    // }

    fn ptrace_access_check(child: *mut task_struct, mode: c_uint) -> Result {

        pr_info!("Ptrace access check!\n");

        unsafe {
            let mut c = get_current_exported();
            let mut parent = ptrace_parent_exported(child);
            if parent != null_mut() {
                pr_info!("child's parent: {}\n", (*parent).pid);
            }
        }

        let mut ret = Ok(());

        if (mode & PTRACE_MODE_ATTACH) != 0 {

            pr_info!("Ptrace attach!\n");

            match unsafe { PTRACE_SCOPE } {
                YAMA_RUST_SCOPE_DISABLED => {
                    ret = Ok(());
                },
                YAMA_RUST_SCOPE_RELATIONAL => {
                    unsafe { rcu_read_lock_exported(); }
                    let child_alive =  unsafe { 
                        pid_alive(child)
                    };
                    let is_descendant = unsafe {
                        task_is_descendant(get_current_exported(), child)
                    };
                    let exception_found = unsafe {
                        ptracer_exception_found(get_current_exported(), child)
                    };
                    let has_capability = unsafe {
                        ns_capable_exported(
                            (*__task_cred_exported(child)).user_ns,
                            CAP_SYS_PTRACE.try_into().unwrap(),
                        ) > 0
                    };
                    pr_info!("Alive: {}, Capability: {}, Is Descendant: {}, Exception: {}\n", child_alive, has_capability, is_descendant, exception_found);
                    if child_alive && !is_descendant && !exception_found && !has_capability {
                        pr_info!("Denied!\n");
                        ret = Err(Error::EPERM);
                    }
                    unsafe { rcu_read_unlock_exported(); }
                },
                YAMA_RUST_SCOPE_CAPABILITY => {
                    unsafe { rcu_read_lock_exported(); }
                    let has_capability = unsafe {
                        ns_capable_exported(
                            (*__task_cred_exported(child)).user_ns,
                            CAP_SYS_PTRACE.try_into().unwrap(),
                        ) != 0
                    };
                    if !has_capability {
                        pr_info!("Denied!\n");
                        ret = Err(Error::EPERM);
                    }
                    unsafe { rcu_read_unlock_exported(); }
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

    fn ptrace_traceme(parent: *mut task_struct) -> Result {
        unsafe {

            let mut ret = Ok(());

            if PTRACE_SCOPE == YAMA_RUST_SCOPE_CAPABILITY {
                let has_capability = unsafe {
                   has_ns_capability(parent, current_user_ns_exported(), CAP_SYS_PTRACE.try_into().unwrap())
                };
                if !has_capability {
                    ret = Err(Error::EPERM);
                    pr_info!("Traceme denied!\n");
                }
            } else if PTRACE_SCOPE == YAMA_RUST_SCOPE_NO_ATTACH {
                pr_info!("Traceme denied!\n");
                ret = Err(Error::EPERM);
            } else {
                pr_info!("Traceme permitted!\n");
            }

            return ret;
        }
    }

    fn task_free(task: *mut task_struct) {
        unsafe { yama_ptracer_del(task, task); }
    }

    fn task_prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> Result {
        
        let mut ret = Err(Error::ENOSYS);
        let mut myself = unsafe { get_current_exported() };

        unsafe {
            if option == PR_SET_PTRACER as c_int {
                rcu_read_lock_exported();
                if !thread_group_leader(myself) {
                    myself = rcu_dereference_exported(&mut (*myself).group_leader as *mut *mut _ as *mut *mut c_void) as *mut task_struct;
                }
                get_task_struct_exported(myself);
                rcu_read_unlock_exported();

                // no tracing permitted
                if arg2 == 0 {
                    pr_info!("Removing tracee relationship!\n");
                    yama_ptracer_del(null_mut(), myself);
                    ret = Ok(());
                } else if arg2 as i32 == -1 {
                    pr_info!("Adding tracee relationship: any tracer!\n");
                    yama_ptracer_add(null_mut(), myself);
                } else {
                    pr_info!("Adding tracee relationship!\n");
                    let tracer = find_get_task_by_vpid(arg2 as pid_t);
                    if tracer == null_mut() {
                        ret = Err(Error::EINVAL);
                    } else {
                        yama_ptracer_add(tracer, myself);
                        ret = Ok(());
                        put_task_struct_exported(tracer);
                    }
                }
                put_task_struct_exported(myself);

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
        // unsafe {
        //     ptracer_relations = Some(Pin::from(Box::try_new(SpinLock::new(List::new()))?));
        //     if let Some(ref mut p) = &mut ptracer_relations {
        //         let a = &mut *p.lock();
        //         pr_info!("Empty: {}\n", a.is_empty());
        //     }
        // }

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
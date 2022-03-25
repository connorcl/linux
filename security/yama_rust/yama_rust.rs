//! A Rust port of Yama, designed to use safe Rust interfaces to the maximum extent

use core::cell::UnsafeCell;
use core::convert::TryInto;
use kernel::bindings::*;
use kernel::c_str;
use kernel::c_types::*;
use kernel::gen_sysctl_path;
use kernel::prelude::*;
use kernel::sync::*;
use kernel::yama_rust_interfaces::context::*;
use kernel::yama_rust_interfaces::rcu::rcu_list::*;
use kernel::yama_rust_interfaces::rcu::*;
use kernel::yama_rust_interfaces::security_module::*;
use kernel::yama_rust_interfaces::sysctl::*;
use kernel::yama_rust_interfaces::task::*;
use kernel::yama_rust_interfaces::work_queue::*;
use kernel::Error;
use kernel::{define_lsm, init_static_sync, init_static_work_struct};

define_lsm!(
    "yama_rust",
    YamaRust,
    ptrace_access_check,
    ptrace_traceme,
    task_free,
    task_prctl
);

init_static_sync! {
    static PTRACE_RELATION_LIST_WRITE_LOCK: SpinLock<()> = ();
}

init_static_work_struct! {
    static PTRACE_RELATION_LIST_CLEANUP_WORK: StaticWorkStruct<PtraceRelationListCleanup>;
}

static PTRACE_SCOPE: BoundedInt = BoundedInt::new(
    YAMA_RUST_SCOPE_RELATIONAL,
    YAMA_RUST_SCOPE_DISABLED,
    YAMA_RUST_SCOPE_NO_ATTACH,
);

static PTRACE_SCOPE_SYSCTL_ENTRY: SysctlInt<PtraceScopeWriteHook> = SysctlInt::init(
        &PTRACE_SCOPE,
        c_str!("ptrace_scope"),
        0o0644,
        gen_sysctl_path!("kernel", "yama"),
);

static PTRACER_RELATIONS: PtraceRelationList = PtraceRelationList::new();

struct PtraceRelationListCleanup;

impl StaticWorkFunc for PtraceRelationListCleanup {
    fn work_func() {
        //pr_info!("Relation cleanup from work queue!\n");
        PTRACER_RELATIONS.cleanup_relations();
    }
}

struct AccessReportInfo {
    access: &'static CStr,
    target: TaskStruct,
    agent: TaskStruct,
}

struct ReportAccess;

impl DynamicWorkFunc for ReportAccess {
    type AssociatedDataType = AccessReportInfo;

    fn work_func(data: &AccessReportInfo) {
        let target_cmdline = data.target.get_ref().get_cmdline_str();
        let agent_cmdline = data.agent.get_ref().get_cmdline_str();
        let target_cmdline = if let Some(ref t) = target_cmdline {
            &*t
        } else {
            c_str!("")
        };
        let agent_cmdline = if let Some(ref a) = agent_cmdline {
            &*a
        } else {
            c_str!("")
        };
        pr_notice!(
            "ptrace {} of \"{}\"[{}] was attempted by \"{}\"[{}]\n", 
            data.access,
            target_cmdline,
            data.target.get_ref().pid(),
            agent_cmdline,
            data.agent.get_ref().pid(),
        );
    }
}

type ReportAccessTask = DynamicWorkStruct<ReportAccess>;

fn report_access(access: &'static CStr, target: TaskStructRef<'_>, agent: TaskStructRef<'_>, event_ctx: EventContextRef<'_>) {
    let info = AccessReportInfo {
        access: access,
        target: target.get_task_struct(),
        agent: agent.get_task_struct(),
    };

    let current = TaskStructRef::current(event_ctx);
    if current.flags_set(PF_KTHREAD) {
        ReportAccess::work_func(&info);
    } else {
        ReportAccessTask::create_and_schedule(info);
    }
}

// #[derive(Copy, Clone)]
// enum PtraceScope {
//     Disabled = 0,
//     Relational = 1,
//     Capability = 2,
//     NoAttach = 3,
// }

const YAMA_RUST_SCOPE_DISABLED: i32 = 0;
const YAMA_RUST_SCOPE_RELATIONAL: i32 = 1;
const YAMA_RUST_SCOPE_CAPABILITY: i32 = 2;
const YAMA_RUST_SCOPE_NO_ATTACH: i32 = 3;

// impl PtraceScope {
//     pub(crate) const fn max() -> i32 {
//         PtraceScope::NoAttach as i32
//     }

//     pub(crate) const fn min() -> i32 {
//         PtraceScope::Disabled as i32
//     }

//     pub(crate) const fn default() -> i32 {
//         PtraceScope::Relational as i32
//     }

//     pub(crate) fn from_int(x: i32) -> PtraceScope {
//         match x {
            
//         }
//         if x <= >
//         if x == PtraceScope::Disabled as i32 {
//             Some(PtraceScope::Disabled)
//         } else if x == PtraceScope::Relational as i32 {
//             Some(PtraceScope::Relational)
//         } else if x == PtraceScope::Capability as i32 {
//             Some(PtraceScope::Capability)
//         } else if x == PtraceScope::NoAttach as i32 {
//             Some(PtraceScope::NoAttach)
//         } else {
//             None
//         }
//     }

//     pub(crate) const fn to_int(&self) -> i32 {
//         *self as i32
//     }
// }

struct PtraceScopeWriteHook;

impl SysctlIntWriteHook for PtraceScopeWriteHook {
    fn write_hook(table: &mut SysctlTable) -> Result {
        if !current_capable(CAP_SYS_PTRACE.try_into().unwrap()) {
            pr_info!("Setting ptrace scope not permitted!\n");
            return Err(Error::EPERM);
        }

        if table.get_data() == table.get_max() {
            pr_info!("Locking scope to highest value!\n");
            table.lock_max();
        }

        Ok(())
    }
}

#[derive(Copy, Clone)]
enum PtraceRelation {
    AnyTracer {
        tracee: TaskStructID,
    },
    TracerTracee {
        tracer: TaskStructID,
        tracee: TaskStructID,
    },
}

impl PtraceRelation {
    fn get_tracee(&self) -> TaskStructID {
        match self {
            PtraceRelation::AnyTracer { tracee } => *tracee,
            PtraceRelation::TracerTracee { tracer: _, tracee } => *tracee,
        }
    }
}

struct PtraceRelationNode {
    relation: PtraceRelation,
    rcu_head: RCUHead,
    pub(crate) invalid: bool,
    links: RCULinks<PtraceRelationNode>,
}

impl PtraceRelationNode {
    pub(crate) fn new(relation: PtraceRelation, invalid: bool) -> PtraceRelationNode {
        return PtraceRelationNode {
            relation,
            rcu_head: RCUHead::new(),
            invalid,
            links: RCULinks::new(),
        };
    }

    fn matches_tracee(&self, tracer_task: TaskStructRef<'_>, tracee_task: TaskStructRef<'_>, ctx: RCUReadLockRef<'_>) -> bool {
        if !self.invalid {
            match self.relation {
                PtraceRelation::AnyTracer { tracee } => {
                    if tracee_task.get_id() == tracee {
                        return true
                    }
                },
                PtraceRelation::TracerTracee { tracer, tracee } => {
                    if tracee_task.get_id() == tracee {
                        let tmp_tracer_ref = unsafe {
                            tracer.get_tmp_ref()
                        };
                        return tmp_tracer_ref.is_descendant(tracer_task, ctx);
                    }
                }
            }
        }
        return false
    }
}

impl GetRCUHead for PtraceRelationNode {
    #[inline]
    fn get_rcu_head(&self) -> &RCUHead {
        &self.rcu_head
    }
}

impl RCUGetLinks for PtraceRelationNode {
    type EntryType = PtraceRelationNode;

    #[inline]
    fn get_links(data: &Self::EntryType) -> &RCULinks<Self::EntryType> {
        &data.links
    }
}

struct PtraceRelationList {
    list: UnsafeCell<RCUList<PtraceRelationNode>>,
}

unsafe impl Sync for PtraceRelationList { }

impl PtraceRelationList {

    pub(crate) const fn new() -> PtraceRelationList {
        PtraceRelationList { list: UnsafeCell::new(RCUList::new()) }
    }

    pub(crate) fn cleanup_relations(&self) {
        // lock spinlock to synchronize mutable access to list
        let _lock = PTRACE_RELATION_LIST_WRITE_LOCK.lock();
        // get reference to list: safe as lock is held
        let list = unsafe { &mut *self.list.get() };
        // enter RCU critical section
        with_rcu_read_lock(|ctx| {
            // get a write-enabled cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_mut_rcu(ctx);
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation) = cursor.current() {
                // check if the relation is invalid and remove if so
                if relation.invalid {
                    // pr_info!("Removing invalid relationship!\n");
                    cursor.remove_current_rcu();
                } else {
                    cursor.move_next_rcu();
                }
            }
        });
    }

    pub(crate) fn add_relation(&self, relation: PtraceRelation) {
        
        // let a = unsafe { ktime_get() };

        // allocate memory for new item
        let new_item = Box::try_new(PtraceRelationNode::new(relation, false));

        if let Ok(n) = new_item {
            // lock spinlock to synchronize mutable access to list
            let _lock = PTRACE_RELATION_LIST_WRITE_LOCK.lock();
            
            // get reference to list: safe as lock is held
            let list = unsafe { &mut *self.list.get() };

            // let b = unsafe { ktime_get() };
            
            // let c = unsafe { ktime_get() };
            
            // enter RCU critical section
            with_rcu_read_lock(|ctx| {

                let relation_tracee = n.relation.get_tracee();
                
                // get a cursor pointing to the first element of the list
                let mut cursor = list.cursor_front_mut_rcu(ctx);
                // unwrap each element of the list in turn, moving the cursor along
                
                let mut count = 0;

                while let Some(relation_node) = cursor.current() {
                    count += 1;
                    if !relation_node.invalid {
                        // pr_info!("Valid!\n");
                        // update tracer if an existing relationship is present
                        let t = relation_node.relation.get_tracee();
                        // pr_info!("t: {}, new relation_tracee: {}\n", t.get_ptr() as usize, relation_tracee.get_ptr() as usize);
                        if t == relation_tracee {
                            // pr_info!("Replacing relationship! count: {}\n", count);
                            cursor.replace_current_rcu(n);
                            return;
                        }
                    }
                    
                    cursor.move_next_rcu();
                }

                // pr_info!("Adding new relationship! count: {}\n", count);
                // if an existing relationship wasn't found, add a new one
                
                // let d = unsafe { ktime_get() };
                
                list.push_front_rcu(n, ctx);

                // let e = unsafe { ktime_get() };
                // pr_info!("Add time: {}\n", e-a);
                // pr_info!("Times: {}, {}, {}, {}. Total: {}, Count: {}\n", b - a, c - b, d - c, e - d, e - a, count);
            });
        }
    }

    pub(crate) fn del_relation(
        &self,
        tracer_task: Option<TaskStructID>,
        tracee_task: Option<TaskStructID>,
    ) {
        // get reference to list: safe as methods are safe
        // even with concurrent mutable access to list
        let list = unsafe { &*self.list.get() };
        // enter RCU critical section
        with_rcu_read_lock(|ctx| {
            let mut marked = false;
            // get a cursor pointing to the first element of the list,
            // safe as write accesses (setting invalid) are safe -
            // worst case invalid is set for an old item
            // which is then removed
            let mut cursor = list.cursor_front_inplace_mut_rcu(ctx);
            // let mut count = 0;
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation_node_ptr) = cursor.current_mut() {
                // SAFETY: read access to current item is always safe
                let relation_node = unsafe { &*relation_node_ptr };
                // count = count + 1;
                if !relation_node.invalid {
                    if let Some(t) = &tracer_task {
                        if let PtraceRelation::TracerTracee { tracer, tracee: _ } =
                            &relation_node.relation
                        {
                            if *t == *tracer {
                                // pr_info!("Found match, marking relationship as invalid!\n");
                                // SAFETY: updating invalid is safe, see above
                                unsafe {
                                    (*relation_node_ptr).invalid = true;
                                }
                                marked = true;
                            }
                        }
                    }
                    // obs - help consider borrowing here - move during loop
                    if let Some(t) = &tracee_task {
                        // SAFETY: reading current item is always safe
                        if *t == relation_node.relation.get_tracee() {
                            // pr_info!("Found match, marking relationship as invalid!\n");
                            // SAFETY: updating invalid is safe, see above
                            unsafe {
                                (*relation_node_ptr).invalid = true;
                            }
                            marked = true;
                        }
                    }
                }
                cursor.move_next_rcu();
            }
            // pr_info!("Relationships: {}\n", count);

            if marked {
                // pr_info!("Marked!\n");
                PTRACE_RELATION_LIST_CLEANUP_WORK.schedule();
            }
        });
    }

    pub(crate) fn exception_found(
        &self,
        tracer_task: TaskStructRef<'_>,
        tracee_task: TaskStructRef<'_>,
        ctx: RCUReadLockRef<'_>,
    ) -> bool {
        // let a = unsafe { ktime_get() };
        let mut tracee_task = tracee_task;
        let parent = tracee_task.get_ptrace_parent(ctx);
        if let Some(p) = parent {
            if p.same_thread_group(tracer_task) {
                // pr_info!("Parent: {}, tracer: {}\n", p.pid(), p.pid());
                // pr_info!("Existing trace relationship!\n");
                // let b = unsafe { ktime_get() };
                // pr_info!("exception found time: {}\n", b-a);
                return true;
            }
        }

        tracee_task = tracee_task.get_thread_group_leader(ctx);

        // get reference to list: safe as accesses will be read only RCU
        let list = unsafe { &*self.list.get() };

        // get a cursor pointing to the first element of the list
        let mut cursor = list.cursor_front_rcu(ctx);
        // unwrap each element of the list in turn, moving the cursor along
        while let Some(relation_node) = cursor.current() {
            if relation_node.matches_tracee(tracer_task, tracee_task, ctx) {
                return true;
            }
            cursor.move_next_rcu();
        }

        return false;
    }
}

struct YamaRust;

impl SecurityModule for YamaRust {
    
    #[inline]
    fn ptrace_access_check(child: TaskStructRef<'_>, mode: u32, event_ctx: EventContextRef<'_>) -> Result {
        // pr_info!("Ptrace access check!\n");

        // static mut times: [i64; 1000] = [0; 1000];
        // static mut times_count: usize = 0;

        // let a = unsafe { ktime_get() };
        // let b = unsafe { ktime_get() };
        // pr_info!("time time: {}\n", b-a);
        
        let mut ret = Ok(());
        let current = TaskStructRef::current(event_ctx);

        if (mode & PTRACE_MODE_ATTACH) != 0 {
            // pr_info!("Ptrace attach!\n");

            match PTRACE_SCOPE.get_val() {
                YAMA_RUST_SCOPE_DISABLED => {
                    ret = Ok(());
                },
                YAMA_RUST_SCOPE_RELATIONAL => {
                    // let b = unsafe { ktime_get() };
                    with_rcu_read_lock(|ctx| {
                        // let lock = RCUReadLock::lock();
                        // let ctx = lock.get_ref();

                        if !child.pid_alive() {
                            ret = Err(Error::EPERM)
                        }
                        if ret.is_ok() && 
                            !current.is_descendant(child, ctx) &&
                            !PTRACER_RELATIONS.exception_found(current, child, ctx) &&
                            !child.current_ns_capable(CAP_SYS_PTRACE, ctx)
                        {
                            // pr_info!("Denied!\n");
                            ret = Err(Error::EPERM)
                        }
                    });
                },
                YAMA_RUST_SCOPE_CAPABILITY => {
                    ret = with_rcu_read_lock(|ctx| {
                        let has_capability = child.current_ns_capable(CAP_SYS_PTRACE, ctx);
                        if !has_capability {
                            // pr_info!("Denied!\n");
                            Err(Error::EPERM)
                        } else {
                            Ok(())
                        }
                    });
                },
                YAMA_RUST_SCOPE_NO_ATTACH => {
                    // pr_info!("Denied!\n");
                    ret = Err(Error::EPERM);
                },
                _ => {
                    // pr_info!("Denied!\n");
                    ret = Err(Error::EPERM);
                }
            }
        }

        if ret.is_err() && (mode & PTRACE_MODE_NOAUDIT == 0) {
            report_access(c_str!("attach"), current, child, event_ctx);
        }

        // let b = unsafe { ktime_get() };

        // pr_info!("ptrace_access_check time: {}\n", b-a);
        
        // unsafe {
        //     times[times_count] = b-a;
        //     times_count += 1;
        //     if times_count == 1000 {
        //         for i in 0..1000 {
        //             pr_info!("ptrace_access_check time: {}\n", times[i]);
        //         }
        //         times_count = 0;
        //     }
        // }

        return ret;
    }

    fn ptrace_traceme(parent: TaskStructRef<'_>, event_ctx: EventContextRef<'_>) -> Result {
        let mut ret = Ok(());

        match PTRACE_SCOPE.get_val() {
            YAMA_RUST_SCOPE_CAPABILITY => {
                let has_capability = parent.has_ns_capability_current(CAP_SYS_PTRACE);
                if !has_capability {
                    ret = Err(Error::EPERM);
                    pr_info!("Traceme denied!\n");
                }
            },
            YAMA_RUST_SCOPE_NO_ATTACH => {
                pr_info!("Traceme denied!\n");
                ret = Err(Error::EPERM);
            },
            _ => {
                // pr_info!("Traceme permitted!\n");
            }
        }

        if ret.is_err() {
            let current = TaskStructRef::current(event_ctx);
            report_access(c_str!("traceme"), parent, current, event_ctx);
        }

        return ret;
    }

    fn task_free(task: TaskStructRef<'_>, event_ctx: EventContextRef<'_>) {
        // pr_info!("Task free!\n");
        PTRACER_RELATIONS.del_relation(Some(task.get_id()), Some(task.get_id()));
    }

    fn task_prctl(
        option: c_int,
        arg2: c_ulong,
        _arg3: c_ulong,
        _arg4: c_ulong,
        _arg5: c_ulong,
        event_ctx: EventContextRef<'_>,
    ) -> Result {

        
        // static mut times: [i64; 1000] = [0; 1000];
        // static mut times_count: usize = 0;
        unsafe { rcu_read_lock_exported() };
        
        let a = unsafe { ktime_get() };

        let mut x = 1234;
        let mut y = 5678;
        let mut p = &mut x as *mut _;


        for i in 0..1000 {
            unsafe {
                // rcu_read_lock_exported();
                // rcu_dereference_exported(&mut p as *mut *mut _ as *mut *mut c_void);
                rcu_assign_pointer_exported(&mut p as *mut *mut _ as *mut *mut c_void, &mut x as *mut _ as *mut _);
                // rcu_assign_pointer_exported(&mut p as *mut *mut _ as *mut *mut c_void, &mut y as *mut _ as *mut _);
                // rcu_read_unlock_exported();
            }
        }

        let b = unsafe { ktime_get() };

        pr_info!("time: {}\n", b-a);

        unsafe { rcu_read_unlock_exported() };

        // for i in 0..1000 {
        //     unsafe {
        //         // rcu_read_lock_exported();
        //         // rcu_dereference_exported(&mut p as *mut *mut _ as *mut *mut c_void);
        //         // rcu_assign_pointer_exported(&mut p as *mut *mut _ as *mut *mut c_void, &mut x as *mut _ as *mut _);
        //         // rcu_assign_pointer_exported(&mut p as *mut *mut _ as *mut *mut c_void, &mut y as *mut _ as *mut _);
        //         rcu_read_unlock_exported();
        //     }
        // }

        
        let mut ret = Err(Error::ENOSYS);

        if option == PR_SET_PTRACER as c_int {
            let myself = with_rcu_read_lock(|ctx| {
                let current = TaskStructRef::current(event_ctx);
                current.get_thread_group_leader(ctx).get_task_struct()
            });

            // no tracing permitted
            if arg2 == 0 {
                // pr_info!("Removing tracee relationship!\n");
                PTRACER_RELATIONS.del_relation(None, Some(myself.get_id()));
                ret = Ok(());
            } else if arg2 as i32 == -1 {
                // pr_info!("Adding tracee relationship: any tracer!\n");
                PTRACER_RELATIONS.add_relation(PtraceRelation::AnyTracer { tracee: myself.get_id() });
                ret = Ok(());
            } else {
                // pr_info!("Adding tracee relationship!\n");
                match TaskStruct::from_pid(arg2 as pid_t) {
                    Some(t) => {
                        PTRACER_RELATIONS.add_relation(PtraceRelation::TracerTracee {
                            tracer: t.get_id(),
                            tracee: myself.get_id(),
                        });
                        ret = Ok(());
                    }
                    None => {
                        ret = Err(Error::EINVAL);
                    }
                }
            }
        }

        // let b = unsafe { ktime_get() };

        // unsafe {
        //     times[times_count] = b-a;
        //     times_count += 1;
        //     if times_count == 1000 {
        //         for i in 0..1000 {
        //             pr_info!("prctl time: {}\n", times[i]);
        //         }
        //         times_count = 0;
        //     }
        // }

        
        // pr_info!("prctl time: {}\n", b-a);

        return ret;
    }

    #[link_section = ".init.text"]
    fn init(hooks: &'static mut SecurityHookList, init_ctx: InitContextRef<'_>) -> Result {
        pr_info!("Initializing Yama-Rust!\n");

        hooks.register(init_ctx);

        PTRACE_SCOPE_SYSCTL_ENTRY.register();

        Ok(())
    }
}
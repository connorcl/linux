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

// Yama permissiveness values
const YAMA_RUST_SCOPE_DISABLED: i32 = 0;
const YAMA_RUST_SCOPE_RELATIONAL: i32 = 1;
const YAMA_RUST_SCOPE_CAPABILITY: i32 = 2;
const YAMA_RUST_SCOPE_NO_ATTACH: i32 = 3;

// define the LSM 'yama_rust', specifying its hook functions and
// the type which implements these
define_lsm!(
    "yama_rust",
    YamaRust,
    ptrace_access_check,
    ptrace_traceme,
    task_free,
    task_prctl
);

// the list of registered tracer-tracee relations
static PTRACER_RELATIONS: PtraceRelationList = PtraceRelationList::new();

// spinlock used to synchronize write accesses to the list of
// registered tracing relations, PTRACER_RELATIONS
init_static_sync! {
    static PTRACE_RELATION_LIST_WRITE_LOCK: SpinLock<()> = ();
}

// static work queue task for cleaning up invalid relations
init_static_work_struct! {
    static PTRACE_RELATION_LIST_CLEANUP_WORK: StaticWorkStruct<PtraceRelationListCleanup>;
}

// permissiveness value exported via sysctl
static PTRACE_SCOPE: BoundedInt = BoundedInt::new(
    YAMA_RUST_SCOPE_RELATIONAL,
    YAMA_RUST_SCOPE_DISABLED,
    YAMA_RUST_SCOPE_NO_ATTACH,
);

// sysctl entry for the above permissiveness value
static PTRACE_SCOPE_SYSCTL_ENTRY: SysctlInt<PtraceScopeWriteHook> = SysctlInt::new(
    &PTRACE_SCOPE,
    c_str!("ptrace_scope"),
    0o0644,
    gen_sysctl_path!("kernel", "yama"),
);

struct PtraceRelationListCleanup;

// work queue task function for cleaning up invalid relations
impl StaticWorkFunc for PtraceRelationListCleanup {
    fn work_func() {
        PTRACER_RELATIONS.cleanup_relations();
    }
}

// info needed for reporting an attempted ptrace operation
struct AccessReportInfo {
    access: &'static CStr,
    target: TaskStruct,
    agent: TaskStruct,
}

struct ReportAccess;

// dynamic work function for reporting attempted accesses
impl DynamicWorkFunc for ReportAccess {
    // each task includes info on the attempted access
    type AssociatedDataType = AccessReportInfo;

    fn work_func(data: &AccessReportInfo) {
        // get command line strings for each process
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
        // print notice that access was attempted
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

// report an attempted ptrace access
fn report_access(
    access: &'static CStr,
    target: TaskStructRef<'_>,
    agent: TaskStructRef<'_>,
    event_ctx: EventContextRef<'_>,
) {
    // package relevant info
    let info = AccessReportInfo {
        access: access,
        target: target.get_task_struct(),
        agent: agent.get_task_struct(),
    };
    let current = TaskStructRef::current(event_ctx);
    if current.flags_set(PF_KTHREAD) {
        // report access directly if running in a kernel thread
        ReportAccess::work_func(&info);
    } else {
        // schedule a work queue task to report attempted access
        DynamicWorkStruct::<ReportAccess>::create_and_schedule(info);
    }
}

struct PtraceScopeWriteHook;

// sysctl write hook for configuring permissiveness
impl SysctlIntWriteHook for PtraceScopeWriteHook {
    fn write_hook(table: &mut SysctlTable) -> Result {
        // ensure current task has CAP_SYS_PTRACE capability
        if !current_capable(CAP_SYS_PTRACE.try_into().unwrap()) {
            return Err(Error::EPERM);
        }
        // lock permissiveness to most restrictive (max value) once set
        if table.get_data() == table.get_max() {
            table.lock_max();
        }
        Ok(())
    }
}

// a permitted tracer-tracee relationship
#[derive(Copy, Clone)]
enum PtraceRelation {
    // any tracer permitted
    AnyTracer {
        tracee: TaskStructID,
    },
    // specific tracer permitted
    TracerTracee {
        tracer: TaskStructID,
        tracee: TaskStructID,
    },
}

impl PtraceRelation {
    // convenience method to get tracee
    #[inline]
    fn get_tracee(&self) -> TaskStructID {
        match self {
            PtraceRelation::AnyTracer { tracee } => *tracee,
            PtraceRelation::TracerTracee { tracer: _, tracee } => *tracee,
        }
    }
}

// type for storing a tracing relation in a linked list
struct PtraceRelationNode {
    relation: PtraceRelation,
    rcu_head: RCUHead,
    pub(crate) invalid: bool,
    links: RCULinks<PtraceRelationNode>,
}

impl PtraceRelationNode {
    // create a new node
    pub(crate) fn new(relation: PtraceRelation, invalid: bool) -> PtraceRelationNode {
        return PtraceRelationNode {
            relation,
            rcu_head: RCUHead::new(),
            invalid,
            links: RCULinks::new(),
        };
    }

    // check if the relation matches the given tasks
    fn matches_tracee(
        &self,
        tracer_task: TaskStructRef<'_>,
        tracee_task: TaskStructRef<'_>,
        ctx: RCUReadLockRef<'_>,
    ) -> bool {
        if !self.invalid {
            match self.relation {
                // check if the tracee matches
                PtraceRelation::AnyTracer { tracee } => {
                    if tracee_task.get_id() == tracee {
                        return true;
                    }
                }
                // check if tracee matches and tracer is descendant of permitted tracer
                PtraceRelation::TracerTracee { tracer, tracee } => {
                    if tracee_task.get_id() == tracee {
                        let tmp_tracer_ref = unsafe { tracer.get_tmp_ref() };
                        return tmp_tracer_ref.is_descendant(tracer_task, ctx);
                    }
                }
            }
        }
        return false;
    }
}

// fetch rcu head field
impl GetRCUHead for PtraceRelationNode {
    #[inline]
    fn get_rcu_head(&self) -> &RCUHead {
        &self.rcu_head
    }
}

// fetch rcu links field
impl RCUGetLinks for PtraceRelationNode {
    type EntryType = PtraceRelationNode;

    #[inline]
    fn get_links(data: &Self::EntryType) -> &RCULinks<Self::EntryType> {
        &data.links
    }
}

// RCU-protected list of ptrace relations
struct PtraceRelationList {
    list: UnsafeCell<RCUList<PtraceRelationNode>>,
}

// synchronized via RCU and spinlock
unsafe impl Sync for PtraceRelationList {}

impl PtraceRelationList {
    // initialize an empty list
    pub(crate) const fn new() -> PtraceRelationList {
        PtraceRelationList {
            list: UnsafeCell::new(RCUList::new()),
        }
    }

    // delete invalid relations
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
                    cursor.remove_current_rcu();
                } else {
                    cursor.move_next_rcu();
                }
            }
        });
    }

    // add a new relation
    pub(crate) fn add_relation(&self, relation: PtraceRelation) {
        if let Ok(n) = Box::try_new(PtraceRelationNode::new(relation, false)) {
            // lock spinlock to synchronize mutable access to list
            let _lock = PTRACE_RELATION_LIST_WRITE_LOCK.lock();
            // get reference to list: safe as lock is held
            let list = unsafe { &mut *self.list.get() };
            // enter RCU critical section
            with_rcu_read_lock(|ctx| {
                let relation_tracee = n.relation.get_tracee();
                // get a cursor pointing to the first element of the list
                let mut cursor = list.cursor_front_mut_rcu(ctx);
                // unwrap each element of the list in turn, moving the cursor along
                while let Some(relation_node) = cursor.current() {
                    if !relation_node.invalid {
                        // update tracer if an existing relationship is present
                        let t = relation_node.relation.get_tracee();
                        if t == relation_tracee {
                            cursor.replace_current_rcu(n);
                            return;
                        }
                    }
                    cursor.move_next_rcu();
                }
                // push item onto list
                list.push_front_rcu(n, ctx);
            });
        }
    }

    // delete a relation by marking it as invalid
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
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation_node_ptr) = cursor.current_mut() {
                // SAFETY: read access to current item is always safe
                let relation_node = unsafe { &*relation_node_ptr };
                if !relation_node.invalid {
                    if let Some(t) = &tracer_task {
                        if let PtraceRelation::TracerTracee { tracer, tracee: _ } =
                            &relation_node.relation
                        {
                            if *t == *tracer {
                                // SAFETY: updating invalid is safe, see above
                                unsafe {
                                    (*relation_node_ptr).invalid = true;
                                }
                                marked = true;
                            }
                        }
                    }
                    if let Some(t) = &tracee_task {
                        // SAFETY: reading current item is always safe
                        if *t == relation_node.relation.get_tracee() {
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
            // launch task to perform deletion if any marked as invalid
            if marked {
                PTRACE_RELATION_LIST_CLEANUP_WORK.schedule();
            }
        });
    }

    // check for a matching exception
    pub(crate) fn exception_found(
        &self,
        tracer_task: TaskStructRef<'_>,
        tracee_task: TaskStructRef<'_>,
        ctx: RCUReadLockRef<'_>,
    ) -> bool {
        let mut tracee_task = tracee_task;
        let parent = tracee_task.get_ptrace_parent(ctx);
        if let Some(p) = parent {
            if p.same_thread_group(tracer_task) {
                return true;
            }
        }
        tracee_task = tracee_task.get_thread_group_leader(ctx);
        // SAFETY: accesses will be read only RCU
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
    // Yama's ptrace access check hook
    #[inline]
    fn ptrace_access_check(
        child: TaskStructRef<'_>,
        mode: u32,
        event_ctx: EventContextRef<'_>,
    ) -> Result {
        // unsafe { rcu_read_lock_exported() };

        // let mut x = 1234;
        // let mut y = 5678;
        // let mut p = &mut x as *mut _;
        // let mut rcu_p;

        // let a = unsafe { ktime_get() };

        // for i in 0..1000 {
        //     unsafe {
        //         // rcu_read_lock_exported();
        //         rcu_p = rcu_dereference_exported(&mut p as *mut *mut _ as *mut *mut c_void);
        //         rcu_assign_pointer_exported(&mut p as *mut *mut _ as *mut *mut c_void, &mut x as *mut _ as *mut _);
        //         // rcu_assign_pointer_exported(&mut p as *mut *mut _ as *mut *mut c_void, &mut y as *mut _ as *mut _);
        //         // rcu_read_unlock_exported();
        //     }
        // }

        // let b = unsafe { ktime_get() };

        // pr_info!("RCU lock/unlock time: {}\n", b-a);
        // pr_info!("RCU dereference/assign time: {}\n", b-a);

        // unsafe { rcu_read_unlock_exported() };

        let mut ret = Ok(());
        let current = TaskStructRef::current(event_ctx);
        // process ptrace attach operations
        if (mode & PTRACE_MODE_ATTACH) != 0 {
            // check current mode
            match PTRACE_SCOPE.get_val() {
                // permit all accesses
                YAMA_RUST_SCOPE_DISABLED => {
                    ret = Ok(());
                }
                // permit processes to trace their descendants
                YAMA_RUST_SCOPE_RELATIONAL => {
                    with_rcu_read_lock(|ctx| {
                        // check if child is alive
                        if !child.pid_alive() {
                            ret = Err(Error::EPERM)
                        }
                        // check if task is a child of current, an exception is
                        // registered, or CAP_SYS_PTRACE cap is held
                        if ret.is_ok()
                            && !current.is_descendant(child, ctx)
                            && !PTRACER_RELATIONS.exception_found(current, child, ctx)
                            && !child.current_ns_capable(CAP_SYS_PTRACE, ctx)
                        {
                            ret = Err(Error::EPERM)
                        }
                    });
                }
                // only allow if CAP_SYS_PTRACE cap is held
                YAMA_RUST_SCOPE_CAPABILITY => {
                    ret = with_rcu_read_lock(|ctx| {
                        let has_capability = child.current_ns_capable(CAP_SYS_PTRACE, ctx);
                        if !has_capability {
                            Err(Error::EPERM)
                        } else {
                            Ok(())
                        }
                    });
                }
                // deny all accesses
                YAMA_RUST_SCOPE_NO_ATTACH => {
                    ret = Err(Error::EPERM);
                }
                _ => {
                    ret = Err(Error::EPERM);
                }
            }
        }
        // report denied accesses
        if ret.is_err() && (mode & PTRACE_MODE_NOAUDIT == 0) {
            report_access(c_str!("attach"), current, child, event_ctx);
        }
        return ret;
    }

    // Yama ptrace traceme hook
    fn ptrace_traceme(parent: TaskStructRef<'_>, event_ctx: EventContextRef<'_>) -> Result {
        let mut ret = Ok(());
        // check current mode
        match PTRACE_SCOPE.get_val() {
            // only allow if CAP_SYS_PTRACE capability is held
            YAMA_RUST_SCOPE_CAPABILITY => {
                let has_capability = parent.has_ns_capability_current(CAP_SYS_PTRACE);
                if !has_capability {
                    ret = Err(Error::EPERM);
                }
            }
            // deny all accesses
            YAMA_RUST_SCOPE_NO_ATTACH => {
                ret = Err(Error::EPERM);
            }
            // allow all accesses in other modes
            _ => {}
        }
        // report denied accesses
        if ret.is_err() {
            let current = TaskStructRef::current(event_ctx);
            report_access(c_str!("traceme"), parent, current, event_ctx);
        }
        return ret;
    }

    // Yama task free hook
    fn task_free(task: TaskStructRef<'_>, _event_ctx: EventContextRef<'_>) {
        PTRACER_RELATIONS.del_relation(Some(task.get_id()), Some(task.get_id()));
    }

    // Yama task prctl hook
    fn task_prctl(
        option: c_int,
        arg2: c_ulong,
        _arg3: c_ulong,
        _arg4: c_ulong,
        _arg5: c_ulong,
        event_ctx: EventContextRef<'_>,
    ) -> Result {
        let mut ret = Err(Error::ENOSYS);
        // handle the PR_SET_PTRACER operation
        if option == PR_SET_PTRACER as c_int {
            // get current task thread group leader
            let myself = with_rcu_read_lock(|ctx| {
                let current = TaskStructRef::current(event_ctx);
                current.get_thread_group_leader(ctx).get_task_struct()
            });
            // no tracing permitted
            if arg2 == 0 {
                PTRACER_RELATIONS.del_relation(None, Some(myself.get_id()));
                ret = Ok(());
            // allow any tracer
            } else if arg2 as i32 == -1 {
                PTRACER_RELATIONS.add_relation(PtraceRelation::AnyTracer {
                    tracee: myself.get_id(),
                });
                ret = Ok(());
            // allow a specific tracer
            } else {
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
        return ret;
    }

    // security module initialization function
    #[link_section = ".init.text"]
    fn init(hooks: &'static mut SecurityHookList, init_ctx: InitContextRef<'_>) -> Result {
        pr_info!("Initializing Yama-Rust!\n");
        // register security hooks
        hooks.register(init_ctx);
        // register sysctl entry
        PTRACE_SCOPE_SYSCTL_ENTRY.register();
        Ok(())
    }
}

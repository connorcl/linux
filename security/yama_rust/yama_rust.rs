//! A Rust port of Yama, designed to use safe Rust interfaces to the maximum extent

use core::cell::UnsafeCell;
use core::convert::TryInto;
use kernel::bindings::*;
use kernel::c_str;
use kernel::c_types::*;
use kernel::gen_sysctl_path;
use kernel::prelude::*;
use kernel::sync::*;
use kernel::yama_rust_interfaces::init_context::*;
use kernel::yama_rust_interfaces::rcu::rcu_list::*;
use kernel::yama_rust_interfaces::rcu::*;
use kernel::yama_rust_interfaces::security_module::*;
use kernel::yama_rust_interfaces::sysctl::*;
use kernel::yama_rust_interfaces::task::*;
use kernel::yama_rust_interfaces::work_queue::*;
use kernel::Error;
use kernel::{define_lsm, init_static_sync};

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

static PTRACE_RELATION_LIST_CLEANUP_WORK: StaticWorkStruct<PtraceRelationListCleanup> =
    StaticWorkStruct::new();

static PTRACE_SCOPE: SysctlInt<PtraceScopeSysctlIntHooks> = SysctlInt::new(
    PtraceScope::default(),
    PtraceScope::min(),
    PtraceScope::max(),
    gen_sysctl_path!("kernel", "yama"),
);

static PTRACER_RELATIONS: PtraceRelationList = PtraceRelationList::new();

struct PtraceRelationListCleanup;

impl StaticWorkFunc for PtraceRelationListCleanup {
    fn work_func(_work: *mut work_struct) {
        pr_info!("Relation cleanup from work queue!\n");
        PTRACER_RELATIONS.cleanup_relations();
    }
}

struct AccessReportInfo {
    access: &'static CStr,
    target: Option<TaskStruct>,
    agent: Option<TaskStruct>,
}

struct ReportAccessWorkFunc;

impl DynamicWorkFunc<AccessReportInfo> for ReportAccessWorkFunc {
    fn work_func(data: &AccessReportInfo) {
        pr_info!("Report access: {}\n", data.access);
    }
}

type ReportAccessPayload = DynamicWorkPayload<AccessReportInfo, ReportAccessWorkFunc>;

fn report_access(access: &'static CStr, target: TaskStructRef<'_>, agent: TaskStructRef<'_>) {
    if TaskStruct::current()
        .unwrap()
        .get_ref()
        .flags_set(PF_KTHREAD)
    {
        pr_info!("Report access inline!\n");
        return;
    }

    ReportAccessPayload::create_and_schedule(AccessReportInfo {
        access: access,
        target: Some(target.get_task_struct()),
        agent: Some(agent.get_task_struct()),
    });
}

#[derive(Copy, Clone)]
enum PtraceScope {
    Disabled = 0,
    Relational = 1,
    Capability = 2,
    NoAttach = 3,
}

impl PtraceScope {
    pub(crate) const fn max() -> i32 {
        PtraceScope::NoAttach as i32
    }

    pub(crate) const fn min() -> i32 {
        PtraceScope::Disabled as i32
    }

    pub(crate) const fn default() -> i32 {
        PtraceScope::Relational as i32
    }

    pub(crate) fn from_int(x: i32) -> Option<PtraceScope> {
        if x == PtraceScope::Disabled as i32 {
            Some(PtraceScope::Disabled)
        } else if x == PtraceScope::Relational as i32 {
            Some(PtraceScope::Relational)
        } else if x == PtraceScope::Capability as i32 {
            Some(PtraceScope::Capability)
        } else if x == PtraceScope::NoAttach as i32 {
            Some(PtraceScope::NoAttach)
        } else {
            None
        }
    }

    pub(crate) const fn to_int(&self) -> i32 {
        *self as i32
    }
}

struct PtraceScopeSysctlIntHooks;

impl SysctlIntHooks for PtraceScopeSysctlIntHooks {
    fn write_hook(table: &mut ctl_table) -> Result<()> {
        if current_capable(CAP_SYS_PTRACE.try_into().unwrap()) {
            pr_info!("Setting ptrace scope not permitted!\n");
            return Err(Error::EPERM);
        }

        if unsafe { *(table.data as *mut c_int) } == unsafe { *(table.extra2 as *mut c_int) } {
            pr_info!("Locking scope to highest value!\n");
            table.extra1 = table.extra2;
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
        };
    }

    fn matches_tracee(&self, tracer_task: TaskStructRef<'_>, tracee_task: TaskStructRef<'_>, ctx: RCULockContextRef<'_>) -> bool {
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
                            tracer.get_tmp_ref(ctx)
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
    fn get_rcu_head(&self) -> *mut callback_head {
        &self.rcu_head as *const _ as *mut _
    }
}

impl RCUGetLinks for PtraceRelationNode {
    type EntryType = PtraceRelationNode;

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
                    cursor.remove_current_rcu(ctx);
                } else {
                    cursor.move_next_rcu(ctx);
                }
            }
        });
    }

    pub(crate) fn add_relation(&self, relation: PtraceRelation) {
        
        // let a = unsafe { ktime_get() };

        // allocate memory for new item
        let new_item = Box::try_new(PtraceRelationNode::new(relation, false)).unwrap();

        // lock spinlock to synchronize mutable access to list
        let _lock  = PTRACE_RELATION_LIST_WRITE_LOCK.lock();
        
        // get reference to list: safe as lock is held
        let list = unsafe { &mut *self.list.get() };

        // let b = unsafe { ktime_get() };
        
        // let c = unsafe { ktime_get() };
        
        // enter RCU critical section
        with_rcu_read_lock(|ctx| {

            let relation_tracee = new_item.relation.get_tracee();
            
            // get a cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_mut_rcu(ctx);
            // unwrap each element of the list in turn, moving the cursor along
            
            let mut count = 0;

            while let Some(relation_node) = cursor.current() {
                count += 1;
                if !relation_node.invalid {
                    pr_info!("Valid!\n");
                    // update tracer if an existing relationship is present
                    let t = relation_node.relation.get_tracee();
                    // pr_info!("t: {}, new relation_tracee: {}\n", t.get_ptr() as usize, relation_tracee.get_ptr() as usize);
                    if t == relation_tracee {
                        pr_info!("Replacing relationship! count: {}\n", count);
                        cursor.replace_current_rcu(new_item, ctx);
                        return;
                    }
                }
                
                cursor.move_next_rcu(ctx);
            }

            pr_info!("Adding new relationship! count: {}\n", count);
            // if an existing relationship wasn't found, add a new one
            
            // let d = unsafe { ktime_get() };
            
            list.push_front_rcu(new_item, ctx);

            // let e = unsafe { ktime_get() };
            // pr_info!("Add time: {}\n", e-a);
            // pr_info!("Times: {}, {}, {}, {}. Total: {}, Count: {}\n", b - a, c - b, d - c, e - d, e - a, count);
        });


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
                                pr_info!("Found match, marking relationship as invalid!\n");
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
                            pr_info!("Found match, marking relationship as invalid!\n");
                            // SAFETY: updating invalid is safe, see above
                            unsafe {
                                (*relation_node_ptr).invalid = true;
                            }
                            marked = true;
                        }
                    }
                }
                cursor.move_next_rcu(ctx);
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
    ) -> bool {
        with_rcu_read_lock(|ctx| {
            let mut tracee_task = tracee_task;
            let parent = tracee_task.get_ptrace_parent(ctx);
            if let Some(p) = parent {
                if p.same_thread_group(tracer_task) {
                    // pr_info!("Parent: {}, tracer: {}\n", p.pid(), p.pid());
                    // pr_info!("Existing trace relationship!\n");
                    return true;
                }
            }

            if !tracee_task.thread_group_leader() {
                tracee_task = tracee_task.get_thread_group_leader(ctx).unwrap();
            }

            // get reference to list: safe as accesses will be read only RCU
            let list = unsafe { &*self.list.get() };

            // get a cursor pointing to the first element of the list
            let mut cursor = list.cursor_front_rcu(ctx);
            // unwrap each element of the list in turn, moving the cursor along
            while let Some(relation_node) = cursor.current() {
                if relation_node.matches_tracee(tracer_task, tracee_task, ctx) {
                    return true;
                }
                cursor.move_next_rcu(ctx);
            }

            return false;
        })
    }
}

struct YamaRust;

impl SecurityModule for YamaRust {
    
    fn ptrace_access_check(child: TaskStructRef<'_>, mode: c_uint) -> Result {
        // pr_info!("Ptrace access check!\n");

        let mut ret = Ok(());

        if (mode & PTRACE_MODE_ATTACH) != 0 {
            // pr_info!("Ptrace attach!\n");

            match PtraceScope::from_int(PTRACE_SCOPE.get_value()) {
                Some(PtraceScope::Disabled) => {
                    ret = Ok(());
                }
                Some(PtraceScope::Relational) => {
                    ret = with_rcu_read_lock(|ctx| {
                        let child_alive = child.pid_alive();
                        let is_descendant = TaskStruct::current()
                            .unwrap()
                            .get_ref()
                            .is_descendant(child, ctx);
                        let exception_found = PTRACER_RELATIONS.exception_found(
                            TaskStruct::current().unwrap().get_ref(),
                            child,
                        );
                        let has_capability = child.current_ns_capable(CAP_SYS_PTRACE, ctx);
                        // pr_info!(
                        //     "Alive: {}, Capability: {}, Is Descendant: {}, Exception: {}\n",
                        //     child_alive,
                        //     has_capability,
                        //     is_descendant,
                        //     exception_found
                        // );
                        if child_alive && !is_descendant && !exception_found && !has_capability {
                            pr_info!("Denied!\n");
                            Err(Error::EPERM)
                        } else {
                            Ok(())
                        }
                    });
                }
                Some(PtraceScope::Capability) => {
                    ret = with_rcu_read_lock(|ctx| {
                        let has_capability = child.current_ns_capable(CAP_SYS_PTRACE, ctx);
                        if !has_capability {
                            pr_info!("Denied!\n");
                            Err(Error::EPERM)
                        } else {
                            Ok(())
                        }
                    });
                }
                Some(PtraceScope::NoAttach) => {
                    pr_info!("Denied!\n");
                    ret = Err(Error::EPERM);
                }
                None => {
                    pr_info!("Denied!\n");
                    ret = Err(Error::EPERM);
                }
            }
        }

        return ret;
    }

    fn ptrace_traceme(parent: TaskStructRef<'_>) -> Result {
        let mut ret = Ok(());

        if let Some(PtraceScope::Capability) = PtraceScope::from_int(PTRACE_SCOPE.get_value()) {
            let has_capability = parent.has_ns_capability_current(CAP_SYS_PTRACE);
            if !has_capability {
                ret = Err(Error::EPERM);
                pr_info!("Traceme denied!\n");
            }
        } else if let Some(PtraceScope::NoAttach) = PtraceScope::from_int(PTRACE_SCOPE.get_value())
        {
            pr_info!("Traceme denied!\n");
            ret = Err(Error::EPERM);
        } else {
            // pr_info!("Traceme permitted!\n");
        }

        let current = TaskStruct::current().unwrap();

        report_access(c_str!("Traceme"), parent, current.get_ref());

        return ret;
    }

    fn task_free(task: TaskStructRef<'_>) {
        // pr_info!("Task free!\n");
        PTRACER_RELATIONS.del_relation(Some(task.get_id()), Some(task.get_id()));
    }

    fn task_prctl(
        option: c_int,
        arg2: c_ulong,
        _arg3: c_ulong,
        _arg4: c_ulong,
        _arg5: c_ulong,
    ) -> Result {

        let a = unsafe { ktime_get() };
        
        let mut ret = Err(Error::ENOSYS);

        if option == PR_SET_PTRACER as c_int {
            let myself = with_rcu_read_lock(|ctx| {
                let current = TaskStruct::current().unwrap();
                if current.get_ref().thread_group_leader() {
                    current
                } else {
                    current
                        .get_ref()
                        .get_thread_group_leader(ctx)
                        .unwrap()
                        .get_task_struct()
                }
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

        let b = unsafe { ktime_get() };
        pr_info!("prctl time: {}\n", b-a);

        return ret;
    }

    #[link_section = ".init.text"]
    fn init(hooks: &'static mut SecurityHookList, init_ctx: InitContextRef<'_>) -> Result {
        pr_info!("Initializing Yama-Rust!\n");

        // SAFETY: exclusive write access from this init function,
        // and no read accesses as hooks have not been registered
        unsafe {
            PTRACE_RELATION_LIST_CLEANUP_WORK.init(init_ctx);
        }

        // SAFETY: register() is being called during initialization
        unsafe { hooks.register(init_ctx) };

        // SAFETY: exclusive write access from this init function,
        // and no read accesses until the next line (register)
        unsafe {
            PTRACE_SCOPE.init(c_str!("ptrace_scope"), 0o0644, init_ctx);
        }

        PTRACE_SCOPE.register();

        // match ret {
        //     Ok(_) => {
        //         pr_info!("Hooks registered successfully!\n");
        //         return Ok(());
        //     }
        //     Err(e) => {
        //         pr_info!("Error registering hooks: {}\n", e.to_kernel_errno());
        //         return Err(e);
        //     }
        // }

        Ok(())
    }
}
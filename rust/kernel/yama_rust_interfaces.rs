use crate::prelude::*;
use crate::bindings::*;
use crate::c_types::*;
use crate::error::Error;
use crate::str::CStr;
use core::marker::PhantomData;
use alloc::boxed::Box;
use core::convert::TryInto;
use core::ptr::NonNull;
use core::cell::UnsafeCell;

pub struct SecurityHookList {
    lsm_name: &'static CStr,
    hook_list: &'static mut [security_hook_list],
}

impl SecurityHookList {

    pub const fn new(
        lsm_name: &'static CStr,
        hook_list: &'static mut [security_hook_list]
    ) -> SecurityHookList {
        return SecurityHookList {
            lsm_name, 
            hook_list,
        };
    }

    // Preconditions: must be called during init phase, 
    // reference to hook_list must not exist outside self
    #[link_section = ".init.text"]
    pub unsafe fn register(&mut self) -> Result {
        // check name is null terminated
        // if self.lsm_name.len() <= 1 || self.lsm_name[self.lsm_name.len() - 1] != 0u8 {
        //     pr_info!("Name empty or invalid!\n");
        //     return Err(Error::EINVAL);
        // }
        let hooks_ptr = self.hook_list.as_mut_ptr();
        let hooks_len = self.hook_list.len() as c_int;
        let name_ptr = self.lsm_name.as_char_ptr();
        // SAFETY: FFI call, internal refs are 'static so pointers will remain valid
        unsafe {
            security_add_hooks(hooks_ptr, hooks_len, name_ptr as *mut c_char);
        }

        return Ok(())
    }
}

pub trait SecurityHooks {
    fn bprm_check_security() -> Result {
        return Ok(());
    }

    fn ptrace_access_check(child: TaskStructRef, mode: c_uint) -> Result {
        return Ok(());
    }

    fn ptrace_traceme(parent: TaskStructRef) -> Result {
        return Ok(());
    }

    fn task_free(task: TaskStructRef) {
        return;
    }

    fn task_prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> Result {
        return Ok(());
    }
}

pub struct LSMHooks<T: SecurityHooks> {
    _phantom: PhantomData<T>
}

impl<T: SecurityHooks> LSMHooks<T> {
    pub unsafe extern "C" fn bprm_check_security(bprm: *mut linux_binprm) -> c_int {
        match T::bprm_check_security() {
            Ok(_) => {
                return 0;
            },
            Err(e) => {
                return e.to_kernel_errno();
            }
        }
    }

    pub unsafe extern "C" fn ptrace_access_check(child: *mut task_struct, mode: c_uint) -> c_int {
        let child = unsafe {
            TaskStructRef::from_ptr(child).unwrap()
        };
        match T::ptrace_access_check(child, mode) {
            Ok(_) => {
                return 0;
            },
            Err(e) => {
                return e.to_kernel_errno();
            }
        }
    }

    pub unsafe extern "C" fn ptrace_traceme(parent: *mut task_struct) -> c_int {
        let parent = unsafe {
            TaskStructRef::from_ptr(parent).unwrap()
        };
        match T::ptrace_traceme(parent) {
            Ok(_) => {
                return 0;
            },
            Err(e) => {
                return e.to_kernel_errno();
            }
        }
    }

    pub unsafe extern "C" fn task_free(task: *mut task_struct) {
        let task = unsafe {
            TaskStructRef::from_ptr(task).unwrap()
        };
        T::task_free(task);
    }

    pub unsafe extern "C" fn task_prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> c_int {
        match T::task_prctl(option, arg2, arg3, arg4, arg5) {
            Ok(_) => {
                return 0;
            },
            Err(e) => {
                return e.to_kernel_errno();
            }
        }
    }
}

pub trait SecurityModule {
    fn init(hooks: &mut SecurityHookList) -> Result;
}

pub struct DefineLSMTraitBoundCheck<T: SecurityHooks + SecurityModule> {
    _phantom: PhantomData<T>,
}

impl<T: SecurityHooks + SecurityModule> DefineLSMTraitBoundCheck<T> {
    pub const fn new() -> DefineLSMTraitBoundCheck<T> {
        return DefineLSMTraitBoundCheck { _phantom: PhantomData };
    }
}

// https://stackoverflow.com/questions/34304593/counting-length-of-repetition-in-macro
#[macro_export]
macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + count!($($xs)*));
}

#[macro_export]
macro_rules! define_lsm {
    ( $name:literal, $a:ty, $( $x:ident ),+ ) => {

        // generates a clear error if trait bounds are not satisfied for $a
        static __define_lsm_trait_bound_check: DefineLSMTraitBoundCheck<$a> = DefineLSMTraitBoundCheck::new();

        // variable (not constant) containing LSM name as required by C interfaces
        static __LSM_NAME: &'static $crate::str::CStr = $crate::c_str!($name);

        const i: usize = count!($($x)*);

        static mut __lsm_hooks_raw: [security_hook_list; i] = [
            $(
                security_hook_list {
                    // hook location: bprm_check_security
                    // SAFETY: pointer to be used in C, *mut required
                    head: unsafe { &security_hook_heads.$x as *const _ as *mut _ },
                    // hook function itself
                    hook: security_list_options {
                        $x: Some(LSMHooks::<$a>::$x),
                    },
                    // other items initialized with default values (null pointers)
                    list: hlist_node {
                        next: core::ptr::null_mut(),
                        pprev: core::ptr::null_mut(),
                    },
                    lsm: core::ptr::null_mut(),
                },
            )*
        ];

        static mut __lsm_hooks: SecurityHookList = SecurityHookList::new(
            __LSM_NAME,
            // SAFETY: __lsm_hooks_raw should only be accessed here
            unsafe { &mut __lsm_hooks_raw },
        );

        //  LSM initialization function, stored in init section
        #[link_section = ".init.text"]
        extern "C" fn __lsm_init_fn() -> c_int {
            let ret = unsafe { <$a>::init(&mut __lsm_hooks) };
            match ret {
                Ok(_) => {
                    return 0;
                },
                Err(e) => {
                    return e.to_kernel_errno();
                }
            }
        }

        // register LSM by placing an lsm_info struct into the .lsm_info.init section
        #[link_section = ".lsm_info.init"]
        pub static mut __lsm_info_struct: lsm_info = lsm_info {
            name: __LSM_NAME.as_char_ptr() as *const c_char, // unique LSM name
            order: 0,
            flags: 0,
            enabled: core::ptr::null_mut(),
            init: Some(__lsm_init_fn), // LSM init function
            blobs: core::ptr::null_mut(),
        };
    };
}

// struct to represent RCU lock context
pub struct RCULockContext {
    // private field prevents direct construction
    _phantom: PhantomData<()>,
}

impl RCULockContext {
    pub fn lock() -> RCULockContext {
        unsafe {
            rcu_read_lock_exported();
        }
        RCULockContext {
            _phantom: PhantomData
        }
    }
}

impl Drop for RCULockContext {
    fn drop(&mut self) {
        unsafe {
            rcu_read_unlock_exported();
        }
    }
}

pub fn with_rcu_read_lock<T, F: FnOnce(&RCULockContext) -> T> (f: F) -> T {
    let ctx = RCULockContext::lock();
    f(&ctx)
}

pub fn rcu_dereference<T> (p: *mut *mut T, _ctx: &RCULockContext) -> *mut T {
    unsafe {
        rcu_dereference_exported(p as *mut *mut c_void) as *mut T
    }
}

pub fn rcu_dereference_const<T> (p: *const *const T, _ctx: &RCULockContext) -> *const T {
    unsafe {
        rcu_dereference_exported(p as *mut *mut c_void) as *const T
    }
}

pub fn rcu_assign_pointer<T>(p: *mut *mut T, v: *mut T, _ctx: &RCULockContext) {
    unsafe {
        rcu_assign_pointer_exported(p as *mut *mut c_void, v as *mut c_void);
    }
}

// set callback to free allocated memory
unsafe fn rcu_free<T: GetRCUHead>(p: *mut T, _ctx: &RCULockContext) {
    if p != core::ptr::null_mut() {
        // get pointer to RCU head
        let rcu_head_ptr = unsafe {
            (*p).get_rcu_head()
        };
        // get offset of RCU head
        let rcu_head_offset = (rcu_head_ptr as u64) - (p as u64);
        // convert offset to function pointer type as required by C interface
        let callback: rcu_callback_t = unsafe {
            Some(core::mem::transmute(rcu_head_offset))
        };
        unsafe {
            // set callback to free memory
            call_rcu(rcu_head_ptr, callback);
        }
    }
}

// simple abstraction for task_struct
pub struct TaskStructRef {
    ptr: NonNull<task_struct>,
    got: bool,
}

impl TaskStructRef {
    pub fn from_ptr_get(ptr: *mut task_struct) -> Option<TaskStructRef> {

        let ptr = NonNull::new(ptr);

        if let Some(p) = ptr {
            unsafe {
                get_task_struct_exported(p.as_ptr());
            }
            Some(TaskStructRef {
                ptr: p,
                got: true,
            })
        } else {
            None
        }
    }

    // create from pointer without inc ref count
    // preconditions: ref count does not need incrementing
    pub unsafe fn from_ptr(ptr: *mut task_struct) -> Option<TaskStructRef> {
        
        let ptr = NonNull::new(ptr);

        if let Some(p) = ptr {
            Some(TaskStructRef {
                ptr: p,
                got: false,
            })
        } else {
            None
        }
    }

    pub fn current() -> Option<TaskStructRef> {
        let current = unsafe { 
            get_current_exported() 
        };
        unsafe {
            TaskStructRef::from_ptr(current)
        }
    }

    pub fn current_get() -> Option<TaskStructRef> {
        let current = unsafe { 
            get_current_exported() 
        };
        TaskStructRef::from_ptr_get(current)
    }

    pub fn null(&self) -> bool {
        return false
    }
    
    pub fn get(&mut self) {
        unsafe {
            get_task_struct_exported(self.ptr.as_ptr());
        }
        self.got = true;
    }

    pub unsafe fn get_ptr(&self) -> NonNull<task_struct> {
        self.ptr
    }

    pub fn got(&self) -> bool {
        self.got
    }

    pub fn pid(&self) -> pid_t {
        unsafe {
            (*self.ptr.as_ptr()).pid
        }
    }

    pub fn same_thread_group(&self, other: &TaskStructRef) -> bool {
        unsafe {
            (*self.ptr.as_ptr()).signal == (*other.ptr.as_ptr()).signal
        }
    }

    pub fn thread_group_leader(&self) -> bool {
        unsafe {
            (*self.ptr.as_ptr()).exit_signal >= 0
        }
    }

    pub fn pid_alive(&self) -> bool {
        unsafe {
            (*self.ptr.as_ptr()).thread_pid != core::ptr::null_mut()
        }
    }

    // must be in rcu_read_lock context
    pub fn get_thread_group_leader(self, ctx: &RCULockContext) -> Option<TaskStructRef> {
        if self.thread_group_leader() {
            Some(self)
        } else {
            let ptr_rcu = unsafe { 
                rcu_dereference(&mut (*self.ptr.as_ptr()).group_leader as *mut *mut _, ctx)
            };
            unsafe {
                TaskStructRef::from_ptr(ptr_rcu)
            }
        }
    }

    // must be in rcu_read_lock context
    pub fn get_real_parent(&self, ctx: &RCULockContext) -> Option<TaskStructRef> {
        let parent_ptr = unsafe {
            rcu_dereference(&mut (*self.ptr.as_ptr()).real_parent as *mut *mut _, ctx)
        };
        unsafe {
            TaskStructRef::from_ptr(parent_ptr)
        }
    }

    // must be in rcu_read_lock context
    pub fn get_ptrace_parent(&self, ctx: &RCULockContext) -> Option<TaskStructRef> {
        let parent_ptr = unsafe {
            rcu_dereference(&mut (*self.ptr.as_ptr()).parent as *mut *mut _, ctx)
        };
        unsafe {
            TaskStructRef::from_ptr(parent_ptr)
        }
    }

    // must be in rcu_read_lock context
    pub fn user_ns_capable(&self, cap: u32, ctx: &RCULockContext) -> bool {
        let task_cred = unsafe {
            rcu_dereference_const(&(*self.ptr.as_ptr()).real_cred as *const *const cred, ctx)
        };
        unsafe {
            ns_capable_exported((*task_cred).user_ns, cap.try_into().unwrap()) >= 0    
        }
    }
}

impl Drop for TaskStructRef {
    fn drop(&mut self) {
        unsafe {
            if self.got {
                put_task_struct_exported(self.ptr.as_ptr());
            }
        }
    }
}

impl PartialEq for TaskStructRef {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl Clone for TaskStructRef {
    fn clone(&self) -> TaskStructRef {
        if self.got {
            TaskStructRef::from_ptr_get(self.ptr.as_ptr()).unwrap()
        } else {
            unsafe {
                TaskStructRef::from_ptr(self.ptr.as_ptr()).unwrap()
            }
        }
    }
}


// trait for getting an RCU head field from a struct 
pub trait GetRCUHead {
    fn get_rcu_head(&self) -> *mut callback_head;
}

// RCU smart pointer type
// struct RCUPtr<T: GetRCUHead> {
//     ptr: *mut T,
// }

// impl<T: GetRCUHead> RCUPtr<T> {

//     // allocate new memory
//     pub fn new() -> Option<RCUPtr<T>> {
//         // get size of type T
//         let size = core::mem::size_of::<T>();
//         // attempt to allocate memory of required size
//         let ptr = unsafe {
//             krealloc(core::ptr::null(), size, GFP_KERNEL) as *mut T
//         };
//         if ptr == core::ptr::null_mut() {
//             None
//         } else {
//             Some(RCUPtr { ptr })
//         }
//     }

//     // convert to raw pointer
//     pub fn into_raw(mut ptr: RCUPtr<T>) -> *mut T {
//         // get pointer
//         let inner_ptr = ptr.ptr;
//         // set other ptr to null to prevent memory being freed on drop
//         ptr.ptr = core::ptr::null_mut();
//         // return ptr
//         inner_ptr
//     }

//     pub unsafe fn from_raw(ptr: *mut T) -> Option<RCUPtr<T>> {
//         if ptr == core::ptr::null_mut() {
//             None
//         } else {
//             Some(RCUPtr { ptr })
//         }
//     }

//     // rcu-dereference and return the stored pointer
//     pub unsafe fn rcu_dereference(&self) -> Option<NonNull<T>> {
//         unsafe {
//             NonNull::new(rcu_dereference(&self.ptr as *const *mut T as *mut *mut T))
//         }
//     }

//     // update this pointer from another RCU pointer,
//     // freeing the memory currently referenced
//     // and consuming the passed pointer object
//     pub unsafe fn rcu_assign(&mut self, mut other: RCUPtr<T>) {
//         // remember old pointer for freeing
//         let old_ptr = self.ptr;
//         // atomically update current pointer
//         unsafe {
//             rcu_assign_pointer(
//                 &mut self.ptr as *mut *mut T,
//                 other.ptr,
//             )
//         }
//         // set other ptr to null to prevent memory being freed on drop:
//         // that memory is now managed by this object
//         other.ptr = core::ptr::null_mut();
//         // free memory referenced by old pointer
//         unsafe {
//             rcu_free(old_ptr);
//         }
//     }
// }

// impl<T: GetRCUHead> Drop for RCUPtr<T> {
//     fn drop(&mut self) {
//         unsafe {
//             rcu_free(self.ptr);
//         }
//     }
// }

pub struct RCUListEntry<T> {
    next: *mut T,
    prev: *mut T,
}

pub struct RCULinks<T> {
    entry: UnsafeCell<RCUListEntry<T>>
}

impl<T> RCULinks<T> {

    pub fn new() -> RCULinks<T> {
        RCULinks {
            entry: UnsafeCell::new(RCUListEntry {
                next: core::ptr::null_mut(),
                prev: core::ptr::null_mut(),
            }),
        }
    }

    // rcu-dereference and return the pointer to the next element
    pub fn rcu_dereference_next(&self, ctx: &RCULockContext) -> *mut T {
        let ptr_to_list_entry = unsafe { self.entry.get() };
        let ptr_to_next_ptr = unsafe { &mut (*ptr_to_list_entry).next as *mut *mut T };
        rcu_dereference(ptr_to_next_ptr, ctx)
    }

    // atomically assign the given pointer as the pointer to the next element
    pub fn rcu_assign_next(&self, next: *mut T, ctx: &RCULockContext) {
        let ptr_to_list_entry = unsafe { self.entry.get() };
        let ptr_to_next_ptr = unsafe { &mut (*ptr_to_list_entry).next as *mut *mut T };
        rcu_assign_pointer(ptr_to_next_ptr, next, ctx);
    }
}

pub trait RCUGetLinks {
    
    type EntryType: RCUGetLinks + GetRCUHead;

    fn get_links(data: &mut Self::EntryType) -> &mut RCULinks<Self::EntryType>;
}

pub struct RCUList<T: RCUGetLinks + GetRCUHead> {
    head: *mut T::EntryType,
}

impl<T: RCUGetLinks + GetRCUHead> RCUList<T> {

    pub fn new() -> RCUList<T> {
        RCUList {
            head: core::ptr::null_mut(),
        }
    }

    pub fn cursor_front_mut_rcu<'a>(&'a mut self, ctx: &RCULockContext) -> RCUListCursorMut<'a, T> {
        RCUListCursorMut {
            cur: NonNull::new(rcu_dereference(&mut self.head as *mut *mut T::EntryType, ctx)),
            list: self,
        }
    }

    pub fn push_back_rcu(&mut self, new: Box<T::EntryType>, ctx: &RCULockContext) {
        // get head ptr
        let head = NonNull::new(self.head);
        // convert box to raw pointer to prevent drop
        let ptr_to_new_item = Box::into_raw(new);
        // get list entry for new item
        let ptr_to_new_list_entry = unsafe {
            T::get_links(&mut *ptr_to_new_item).entry.get()
        };

        match head {
            // if the list is not empty
            Some(p) => {
                unsafe {
                    // get list entry for head
                    let ptr_to_head_list_entry = T::get_links(&mut *p.as_ptr()).entry.get();
                    // get ptr to tail
                    let ptr_to_tail_item = (*ptr_to_head_list_entry).prev;
                    // get tail links
                    let tail_links = T::get_links(&mut *ptr_to_tail_item);
                    // get ptr to tail list entry
                    let ptr_to_tail_list_entry = tail_links.entry.get();

                    // set prev and next ptrs for current item
                    (*ptr_to_new_list_entry).prev = ptr_to_tail_item;
                    (*ptr_to_new_list_entry).next = core::ptr::null_mut();

                    // rcu_assign to the tail item's next pointer
                    tail_links.rcu_assign_next(ptr_to_new_item, ctx);

                    // update head's prev pointer
                    (*ptr_to_head_list_entry).prev = ptr_to_new_item;
                }
            },
            // if list is empty
            None => {
                unsafe {
                    // set up next pointer to be null
                    (*ptr_to_new_list_entry).next = core::ptr::null_mut();
                    // set up prev pointer to point to itself (tail)
                    (*ptr_to_new_list_entry).prev = ptr_to_new_item;
                    // rcu_assign to the list's head pointer
                    rcu_assign_pointer(&mut self.head as *mut *mut T::EntryType, ptr_to_new_item, ctx);
                }
            },
        }
    }
}

pub struct RCUListCursor<T: RCUGetLinks + GetRCUHead> {
    cur: Option<NonNull<T::EntryType>>,
}

impl<T: RCUGetLinks + GetRCUHead> RCUListCursor<T> {

    pub fn current(&self) -> Option<&T::EntryType> {
        Some(unsafe { &*self.cur?.as_ptr()} )
    }

    pub fn move_next_rcu(&mut self, ctx: &RCULockContext) {
        if let Some(p) = self.cur {
            let next_ptr = unsafe {
                T::get_links(&mut *p.as_ptr()).rcu_dereference_next(ctx)
            };
            self.cur = NonNull::new(next_ptr);
        }
    }
}

pub struct RCUListCursorMut<'a, T: RCUGetLinks + GetRCUHead> {
    cur: Option<NonNull<T::EntryType>>,
    list: &'a mut RCUList<T>,
}

impl<T: RCUGetLinks + GetRCUHead> RCUListCursorMut<'_, T> {

    pub fn current(&mut self) -> Option<&mut T::EntryType> {
        Some(unsafe { &mut *self.cur?.as_ptr()} )
    }

    pub fn move_next_rcu(&mut self, ctx: &RCULockContext) {
        if let Some(p) = self.cur {
            let next_ptr = unsafe {
                T::get_links(&mut *p.as_ptr()).rcu_dereference_next(ctx)
            };
            self.cur = NonNull::new(next_ptr);
        }
    }

    pub fn remove_current_rcu(&mut self, ctx: &RCULockContext) {
        if let Some(p) = self.cur {
            unsafe {
                // get pointer to current item's list entry
                let ptr_to_cur_list_entry = T::get_links(&mut *p.as_ptr()).entry.get();
                // get pointer to prev item
                let ptr_to_prev_item = (*ptr_to_cur_list_entry).prev;
                // get pointer to next item
                let ptr_to_next_item = (*ptr_to_cur_list_entry).next;

                // if next ptr is not null
                if ptr_to_next_item != core::ptr::null_mut() {
                    // get pointer to next item's list entry
                    let ptr_to_next_list_entry = T::get_links(&mut *ptr_to_next_item).entry.get();
                    // update prev pointer for next item
                    (*ptr_to_next_list_entry).prev = ptr_to_prev_item;
                }

                // if this item is the list head, i.e. prev points to tail
                if p.as_ptr() == self.list.head {
                    // rcu_assign the list's head pointer
                    rcu_assign_pointer(&mut self.list.head as *mut *mut T::EntryType, ptr_to_next_item, ctx);
                } else {
                    // get previous item's links
                    let prev_list_links = T::get_links(&mut *ptr_to_prev_item);
                    // rcu_assign next pointer for prev item
                    prev_list_links.rcu_assign_next(ptr_to_next_item, ctx);
                }
                

                // update self.cur
                self.cur = NonNull::new(ptr_to_next_item);

                // queue removed item for deallocation
                rcu_free(p.as_ptr(), ctx);
            }
        }
    }

    pub fn replace_current_rcu(&mut self, new: Box<T::EntryType>, ctx: &RCULockContext) {
        if let Some(p) = self.cur {
            unsafe {
                // convert box to raw pointer to prevent drop
                let ptr_to_new_item = Box::into_raw(new);
                // get pointer to new item's list entry
                let ptr_to_new_list_entry = T::get_links(&mut *ptr_to_new_item).entry.get();
                // get pointer to current item's list entry
                let ptr_to_cur_list_entry = T::get_links(&mut *p.as_ptr()).entry.get();
                
                // get pointer to prev item
                let ptr_to_prev_item = (*ptr_to_cur_list_entry).prev;
                // get pointer to next item
                let ptr_to_next_item = (*ptr_to_cur_list_entry).next;
                
                // set next and prev pointers for new item
                (*ptr_to_new_list_entry).prev = ptr_to_prev_item;
                (*ptr_to_cur_list_entry).next = ptr_to_next_item;

                // if this item is the list head, i.e. prev points to tail
                if p.as_ptr() == self.list.head {
                    // rcu_assign the list's head pointer
                    rcu_assign_pointer(&mut self.list.head as *mut *mut T::EntryType, ptr_to_new_item, ctx);
                } else {
                    // get previous item's links
                    let prev_list_links = T::get_links(&mut *ptr_to_prev_item);
                    // rcu-assign next pointer for prev item
                    prev_list_links.rcu_assign_next(ptr_to_new_item, ctx);
                }
                
                // set prev pointer for next item
                if ptr_to_next_item != core::ptr::null_mut() {
                    let ptr_to_next_entry = T::get_links(&mut *ptr_to_next_item).entry.get();
                    (*ptr_to_next_entry).prev = ptr_to_new_item;
                }

                // update self.cur
                self.cur = NonNull::new(ptr_to_new_item);

                // queue old item for deallocation
                rcu_free(p.as_ptr(), ctx);
            }
        }
    }
}
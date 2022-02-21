use crate::prelude::*;
use crate::bindings::*;
use crate::c_types::*;
use crate::error::Error;
use crate::str::CStr;
use crate::container_of;
use core::marker::{PhantomData, PhantomPinned};
use alloc::boxed::Box;
use core::convert::TryInto;
use core::ptr::NonNull;
use core::cell::UnsafeCell;
use crate::c_str;

// an abstraction over UnsafeCell that allows mutable 
// access only during init, simplifying its safe use
pub struct InitCell<T> {
    data: UnsafeCell<T>,
}

impl<T> InitCell<T> {
    pub const fn new(data: T) -> InitCell<T> {
        InitCell {
            data: UnsafeCell::new(data),
        }
    }

    #[link_section = ".init.text"]
    pub const fn get(&self, _init_ctx: InitContextRef<'_>) -> *mut T {
        self.data.get()
    }

    pub const fn get_ref(&self) -> &T {
        unsafe { &*self.data.get() }
    }
}

pub struct SecurityHookList {
    lsm_name: &'static CStr,
    hook_list: &'static mut [security_hook_list],
}

pub struct SecurityHookList2<const N: usize> {
    lsm_name: &'static CStr,
    hook_list: [security_hook_list; N],
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
    pub unsafe fn register(&mut self, _init_ctx: InitContextRef<'_>) -> Result {
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
    fn init(hooks: &mut SecurityHookList, init_ctx: InitContextRef<'_>) -> Result;
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
        unsafe extern "C" fn __lsm_init_fn() -> c_int {
            in_init_ctx(|init_ctx| {
                let ret = unsafe { <$a>::init(&mut __lsm_hooks, init_ctx) };
                match ret {
                    Ok(_) => {
                        return 0;
                    },
                    Err(e) => {
                        return e.to_kernel_errno();
                    }
                }
            })
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

// ZST struct to represent RCU lock context
struct RCULockContext {
    // private field prevents direct construction
    _private: (),
}

impl RCULockContext {
    pub(crate) fn lock() -> RCULockContext {
        unsafe {
            rcu_read_lock_exported();
        }
        RCULockContext {
            _private: ()
        }
    }

    // get a zero-size 'reference' type that behaves as if 
    // if holds a reference to self, enforcing that this reference
    // does not outlive self
    pub(crate) fn get_ref<'a>(&'a self) -> RCULockContextRef<'a> {
        RCULockContextRef {
            _phantom: PhantomData,
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

// zero-size simulated 'reference' to a valid RCU lock context
#[derive(Copy, Clone)]
pub struct RCULockContextRef<'a> {
    _phantom: PhantomData<&'a RCULockContext>
}


pub fn with_rcu_read_lock<T, F: FnOnce(RCULockContextRef<'_>) -> T> (f: F) -> T {
    let ctx = RCULockContext::lock();
    f(ctx.get_ref())
}

pub fn rcu_dereference<T> (p: *mut *mut T, _ctx: RCULockContextRef<'_>) -> *mut T {
    unsafe {
        rcu_dereference_exported(p as *mut *mut c_void) as *mut T
    }
}

pub fn rcu_dereference_const<T> (p: *const *const T, _ctx: RCULockContextRef<'_>) -> *const T {
    unsafe {
        rcu_dereference_exported(p as *mut *mut c_void) as *const T
    }
}

pub fn rcu_assign_pointer<T>(p: *mut *mut T, v: *mut T, _ctx: RCULockContextRef<'_>) {
    unsafe {
        rcu_assign_pointer_exported(p as *mut *mut c_void, v as *mut c_void);
    }
}

// set callback to free allocated memory
unsafe fn rcu_free<T: GetRCUHead>(p: *mut T, _ctx: RCULockContextRef<'_>) {
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
    pub fn get_thread_group_leader(self, ctx: RCULockContextRef<'_>) -> Option<TaskStructRef> {
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
    pub fn get_real_parent(&self, ctx: RCULockContextRef<'_>) -> Option<TaskStructRef> {
        let parent_ptr = unsafe {
            rcu_dereference(&mut (*self.ptr.as_ptr()).real_parent as *mut *mut _, ctx)
        };
        unsafe {
            TaskStructRef::from_ptr(parent_ptr)
        }
    }

    // must be in rcu_read_lock context
    pub fn get_ptrace_parent(&self, ctx: RCULockContextRef<'_>) -> Option<TaskStructRef> {
        let parent_ptr = unsafe {
            rcu_dereference(&mut (*self.ptr.as_ptr()).parent as *mut *mut _, ctx)
        };
        unsafe {
            TaskStructRef::from_ptr(parent_ptr)
        }
    }

    // must be in rcu_read_lock context
    pub fn user_ns_capable(&self, cap: u32, ctx: RCULockContextRef<'_>) -> bool {
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
    pub fn rcu_dereference_next(&self, ctx: RCULockContextRef<'_>) -> *mut T {
        let ptr_to_list_entry = unsafe { self.entry.get() };
        let ptr_to_next_ptr = unsafe { &mut (*ptr_to_list_entry).next as *mut *mut T };
        rcu_dereference(ptr_to_next_ptr, ctx)
    }

    // atomically assign the given pointer as the pointer to the next element
    pub fn rcu_assign_next(&self, next: *mut T, ctx: RCULockContextRef<'_>) {
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

    pub fn cursor_front_rcu(&self, ctx: RCULockContextRef<'_>) -> RCUListCursor<T> {
        RCUListCursor {
            cur: NonNull::new(rcu_dereference(&self.head as *const *mut T::EntryType as *mut *mut T::EntryType, ctx)),
        }
    }

    pub fn cursor_front_mut_rcu(&mut self, ctx: RCULockContextRef<'_>) -> RCUListCursorMut<'_, T> {
        RCUListCursorMut {
            cur: NonNull::new(rcu_dereference(&mut self.head as *mut *mut T::EntryType, ctx)),
            list: self,
        }
    }

    pub fn cursor_front_inplace_mut_rcu(&self, ctx: RCULockContextRef<'_>) -> RCUListCursorInplaceMut<T> {
        RCUListCursorInplaceMut {
            cur: NonNull::new(rcu_dereference(&self.head as *const *mut T::EntryType as *mut *mut T::EntryType, ctx)),
        }
    }
 
    pub fn push_back_rcu(&mut self, new: Box<T::EntryType>, ctx: RCULockContextRef<'_>) {
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
        Some(unsafe { &*self.cur?.as_ptr() })
    }

    pub fn move_next_rcu(&mut self, ctx: RCULockContextRef<'_>) {
        if let Some(p) = self.cur {
            let next_ptr = unsafe {
                T::get_links(&mut *p.as_ptr()).rcu_dereference_next(ctx)
            };
            self.cur = NonNull::new(next_ptr);
        }
    }
}

pub struct RCUListCursorInplaceMut<T: RCUGetLinks + GetRCUHead> {
    cur: Option<NonNull<T::EntryType>>,
}

impl<T: RCUGetLinks + GetRCUHead> RCUListCursorInplaceMut<T> {

    pub fn current_mut(&mut self) -> Option<*mut T::EntryType> {
        Some(unsafe { self.cur?.as_ptr() })
    }

    pub fn move_next_rcu(&mut self, ctx: RCULockContextRef<'_>) {
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
    // only one of these cursors per list, but can coexist with
    // regular and inplace (unsafe) cursors
    list: &'a mut RCUList<T>,
}

impl<T: RCUGetLinks + GetRCUHead> RCUListCursorMut<'_, T> {

    pub fn current(&self) -> Option<&T::EntryType> {
        Some(unsafe { &*self.cur?.as_ptr() })
    }

    pub fn move_next_rcu(&mut self, ctx: RCULockContextRef<'_>) {
        if let Some(p) = self.cur {
            let next_ptr = unsafe {
                T::get_links(&mut *p.as_ptr()).rcu_dereference_next(ctx)
            };
            self.cur = NonNull::new(next_ptr);
        }
    }

    pub fn remove_current_rcu(&mut self, ctx: RCULockContextRef<'_>) {
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

    pub fn replace_current_rcu(&mut self, new: Box<T::EntryType>, ctx: RCULockContextRef<'_>) {
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

// static mut yama_relation_work: work_struct = work_struct {
//     data: atomic_long_t {
//         counter: (WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC),
//     },
//     entry: list_head {
//         next: unsafe { &yama_relation_work.entry as *const _ as *mut _ },
//         prev: unsafe { &yama_relation_work.entry as *const _ as *mut _ },
//     },
//     func: Some(yama_relation_cleanup),
// };

// unsafe extern "C" fn yama_relation_cleanup(work: *mut work_struct) {
//     pr_info!("Relation cleanup from work queue!\n");
//     ptracer_relations.cleanup_relations();
// }

struct InitContext {
    _private: PhantomData<()>,
}

impl InitContext {
    // SFAETY: caller must ensure instances do not outlive init context
    unsafe fn new() -> InitContext {
        InitContext {
            _private: PhantomData,
        }
    }

    fn get_ref<'a>(&'a self) -> InitContextRef<'a> {
        return InitContextRef {
            _marker: PhantomData,
        }
    }
}

#[link_section = ".init.text"]
pub fn in_init_ctx<R, F: FnOnce(InitContextRef<'_>) -> R>(f: F) -> R {
    // SAFETY: init context instance is created and dropped
    // in function only callable during init
    let init_ctx = unsafe {
        InitContext::new()
    };
    // call closure
    f(init_ctx.get_ref())
}

#[derive(Copy, Clone)]
pub struct InitContextRef<'a> {
    _marker: PhantomData<&'a InitContext>,
}

pub trait StaticWorkFunc {
    fn work_func(work: *mut work_struct);
}

struct StaticWorkFuncCInterface<T: StaticWorkFunc> {
    _marker: PhantomData<T>,
}

impl<T: StaticWorkFunc> StaticWorkFuncCInterface<T> {
    pub(crate) unsafe extern "C" fn work_func(work: *mut work_struct) {
        T::work_func(work);
    }
}

pub struct StaticWorkStruct<T: StaticWorkFunc> {
    work: InitCell<Option<work_struct>>,
    _marker: PhantomData<T>,
    _pin: PhantomPinned,
}

impl<T: StaticWorkFunc> StaticWorkStruct<T> {

    pub const fn new() -> StaticWorkStruct<T> {
        StaticWorkStruct {
            work: InitCell::new(None),
            _marker: PhantomData,
            _pin: PhantomPinned,
        }
    }

    #[link_section = ".init.text"]
    pub unsafe fn init(&'static self, init_ctx: InitContextRef<'_>) {
        // SAFETY: mutating data is safe during init phase
        unsafe {
            *self.work.get(init_ctx) = Some(
                work_struct {
                    data: atomic_long_t {
                        counter: (WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC),
                    },
                    entry: list_head {
                        next: core::ptr::null_mut(),
                        prev: core::ptr::null_mut(),
                    },
                    func: Some(StaticWorkFuncCInterface::<T>::work_func),
                }
            );
            if let Some(ref mut work) = *self.work.get(init_ctx) {
                work.entry.next = &mut work.entry as *mut _;
                work.entry.prev = &mut work.entry as *mut _;
            }
        }
    }

    pub fn schedule(&'static self) {
        // SAFETY: pointer is guaranteed to be valid and is 
        // immediately converted to an immutable reference
        if let Some(work) = self.work.get_ref() {
            // SAFETY: FFI call, self is static so work will be valid
            unsafe {
                schedule_work_exported(work as *const _ as *mut _);
            }
        }
    }
}

unsafe impl<T: StaticWorkFunc> Sync for StaticWorkStruct<T> { }

pub trait DynamicWorkFunc<T> {
    fn work_func(data: &T);
}

struct DynamicWorkFuncCInterface<T, U: DynamicWorkFunc<T>> {
    _marker_t: PhantomData<T>,
    _marker_u: PhantomData<U>,
}

impl<T, U: DynamicWorkFunc<T>> DynamicWorkFuncCInterface<T, U> {
    pub(crate) unsafe extern "C" fn work_func(work: *mut callback_head) {
        // SAFETY: callback_head pts to field of Box-allocated work payload
        let payload = unsafe {
            Box::from_raw(container_of!(work, DynamicWorkPayload<T, U>, work_head) as *mut DynamicWorkPayload<T, U>)
        };
        U::work_func(&(*payload).data);
        // box goes out of scope and dynamicaly allocated payload is freed
    }
}

pub struct DynamicWorkPayload<T, U: DynamicWorkFunc<T>> {
    data: T,
    work_head: callback_head,
    _marker: PhantomData<U>,
}

impl<T, U: DynamicWorkFunc<T>> DynamicWorkPayload<T, U> {

    pub fn create_and_schedule(data: T) {

        // dynamically allocate a new payload
        let payload: Box<DynamicWorkPayload<T, U>> = Box::try_new(DynamicWorkPayload {
            data: data,
            work_head: callback_head {
                next: core::ptr::null_mut(),
                func: Some(DynamicWorkFuncCInterface::<T, U>::work_func)
            },
            _marker: PhantomData,
        }).unwrap();
        // covert to raw pointer to prevent drop
        let payload = Box::into_raw(payload);

        let current = unsafe {
            TaskStructRef::current().unwrap().get_ptr().as_ptr()
        };

        let ret = unsafe {
            task_work_add(current, &(*payload).work_head as *const _ as *mut _, task_work_notify_mode_TWA_RESUME)
        };
        pr_info!("Task work add: {}\n", ret);
    }
}

#[macro_export]
macro_rules! gen_sysctl_path {
    ( $($p:literal),+ ) => {
        &[
            $(
                ctl_path {
                    procname: c_str!($p).as_char_ptr(),
                },
            )*
            ctl_path {
                procname: core::ptr::null(),
            },
        ]
    }
}

pub trait SysctlIntHooks {
    fn write_hook(table: &mut ctl_table) -> Result<()>;
}

struct SysctlDoIntVecMinMax<T: SysctlIntHooks> {
    _marker: PhantomData<T>,
}

impl<T: SysctlIntHooks> SysctlDoIntVecMinMax<T> {
    pub(crate) unsafe extern "C" fn dointvec_minmax(table: *mut ctl_table, write: c_int,
        buffer: *mut c_void, lenp: *mut c_size_t, ppos: *mut loff_t) -> c_int {

        let mut table_copy = unsafe {
            *table
        };

        if write != 0 {
            if let Err(e) = T::write_hook(&mut table_copy) {
                return e.to_kernel_errno();
            }
        }

        return unsafe {
            proc_dointvec_minmax(&mut table_copy as *mut _, write, buffer, lenp, ppos)
        };
    }
}

pub struct SysctlInt<T: SysctlIntHooks> {
    val: c_int,
    min: c_int,
    max: c_int,
    sysctl_path: &'static [ctl_path],
    sysctl_table: InitCell<Option<[ctl_table; 2]>>,
    _marker: PhantomData<T>,
}

impl<T: SysctlIntHooks> SysctlInt<T> {
    pub const fn new(default: c_int, min: c_int, max: c_int, path: &'static [ctl_path]) -> SysctlInt<T> {
        SysctlInt {
            val: default,
            min: min,
            max: max,
            sysctl_path: path,
            sysctl_table: InitCell::new(None),
            _marker: PhantomData,
        }
    }

    pub const fn get_value(&self) -> c_int {
        self.val
    }

    #[link_section = ".init.text"]
    pub unsafe fn init(&'static self, name: &'static CStr, mode: u16, init_ctx: InitContextRef<'_>) {
        // SAFETY: intialization in init context
        let r = unsafe { &mut *self.sysctl_table.get(init_ctx) };
        *r = Some([
            ctl_table {
                procname: name.as_char_ptr(),
                data: &self.val as *const _ as *mut c_void,
                maxlen: core::mem::size_of::<c_int>() as i32,
                mode: mode as _,
                child: core::ptr::null_mut(),
                proc_handler: Some(SysctlDoIntVecMinMax::<T>::dointvec_minmax),
                poll: core::ptr::null_mut(),
                extra1: &self.min as *const _ as *mut c_void,
                extra2: &self.max as *const _ as *mut c_void,
            },
            ctl_table {
                procname: core::ptr::null(),
                data: core::ptr::null_mut(),
                maxlen: 0,
                mode: 0,
                child: core::ptr::null_mut(),
                proc_handler: None,
                poll: core::ptr::null_mut(),
                extra1: core::ptr::null_mut(),
                extra2: core::ptr::null_mut(),
            },
        ])
    }

    pub fn register(&'static self) {
        if let Some(t) = self.sysctl_table.get_ref() {
            let sret = unsafe {
                register_sysctl_paths(self.sysctl_path.as_ptr() as *const _, 
                    t as *const _ as *mut _)
            };
            let a = sret != core::ptr::null_mut();
            pr_info!("Registering sysctl paths: {}\n", a);
        }
    }
}

unsafe impl<T: SysctlIntHooks> Sync for SysctlInt<T> { }
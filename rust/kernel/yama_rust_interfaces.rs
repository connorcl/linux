//! Interfaces required for the Rust port of Yama
//!
//! These comprise all new interfaces created to support
//! the Rust port of Yama. It is intended that the modules
//! herein will be moved to more suitable locations within
//! the `kernel` crate at a later development stage

/// Compile-time verification of init context
///
/// The types in this module center around a zero-sized
/// reference type which can be used to confirm execution
/// is still in the initialization phase.
pub mod init_context {

    use core::cell::UnsafeCell;
    use core::marker::PhantomData;

    /// RAII object representing init context
    ///
    /// A valid instance of this struct indicates that execution
    /// is still in the init phase.
    pub struct InitContext {
        // prevents direct construction
        _private: PhantomData<()>,
    }

    impl InitContext {
        /// Returns a new `InitContext`
        ///
        /// # Safety
        ///
        /// At the moment, the caller is responsible for ensuring instances
        /// of this struct do not outlive the init phase. There may be a
        /// better way to do this...
        #[link_section = ".init.text"]
        pub unsafe fn new() -> InitContext {
            InitContext {
                _private: PhantomData,
            }
        }

        /// Returns a zero-sized 'reference' to the `InitContext` instance
        ///
        /// These 'references' can be freely copied and passed around as
        /// arguments, and the compiler will ensure they do not outlive the
        ///  `InitContext` they refer to
        pub fn get_ref<'a>(&'a self) -> InitContextRef<'a> {
            return InitContextRef {
                _marker: PhantomData,
            };
        }
    }

    /// A zero-sized 'reference' tied to a specific `InitContext` instance
    ///
    /// Instances of this type can be freely copied and passed around as
    /// arguments, and the compiler will ensure they do not outlive the
    ///  `InitContext` they refer to. The only way to create an instance
    /// of this type is to call `get_ref` on an instance of `InitContext`
    #[derive(Copy, Clone)]
    pub struct InitContextRef<'a> {
        // phantom 'reference'
        _marker: PhantomData<&'a InitContext>,
    }

    /// A cell which only allows mutable access during initialization
    ///
    /// This type is a simple layer over `UnsafeCell` which only allows
    /// gaining a raw pointer to the underlying data if an `InitContextRef`
    /// is provided, confirming execution is in the initialization stage.
    ///
    /// This is useful for initializing data which cannot be initialized
    /// statically, providing a safer option than a simple UnsafeCell
    pub struct InitCell<T> {
        data: UnsafeCell<T>,
    }

    impl<T> InitCell<T> {
        /// Returns a new `InitCell`
        ///
        /// This simply initializes the underlying `UnsafeCell`
        pub const fn new(data: T) -> InitCell<T> {
            InitCell {
                data: UnsafeCell::new(data),
            }
        }

        /// Returns a raw pointer to the underlying data
        ///
        /// # Arguments
        ///
        /// * _init_ctx: An `InitContextRef` to confirm execution is in
        /// the intiialization phase.
        #[link_section = ".init.text"]
        pub const fn get(&self, _init_ctx: InitContextRef<'_>) -> *mut T {
            self.data.get()
        }

        /// Returns an immutable reference to the underlying data
        pub const fn get_ref(&self) -> &T {
            unsafe { &*self.data.get() }
        }
    }
}

/// Abstractions to the Linux security module subsystem
///
/// This includes the necessary interfaces for initializing
/// a security module and specifying security subsystem hooks
pub mod security_module {

    use crate::bindings::*;
    use crate::c_types::*;
    use crate::prelude::*;
    use crate::str::CStr;
    use crate::yama_rust_interfaces::init_context::*;
    use crate::yama_rust_interfaces::task::TaskStructRef;
    use core::marker::PhantomData;

    /// A list of security hook specifications
    ///
    /// Stores references to an LSM name and a list of security hooks.
    /// This type will usually not be used directly, but by the macro
    /// `define_lsm`.
    pub struct SecurityHookList {
        lsm_name: &'static CStr,
        hook_list: &'static mut [security_hook_list],
    }

    impl SecurityHookList {
        /// Returns a new `SecurityHookList`
        ///
        /// # Arguments
        ///
        /// * lsm_name: A static reference to a C string holding the LSM's name
        /// * hook_list: A static, mutable slice containing each relevant
        /// security hook list
        pub const fn new(
            lsm_name: &'static CStr,
            hook_list: &'static mut [security_hook_list],
        ) -> SecurityHookList {
            return SecurityHookList {
                lsm_name,
                hook_list,
            };
        }

        /// Registers the list of security hooks
        ///
        ///
        /// # Arguments
        ///
        /// * _init_ctx: An `InitContextRef` to confirm execution is in
        /// the intiialization phase.
        ///
        /// # Safety
        ///
        /// This method should not be called concurrently, and there should
        /// be no concurrent access to the raw list of security hooks
        /// referred to by the underlyinf type. If the `define_lsm` macro is used,
        /// and this method only called within the security module `init` method,
        /// these conditions should be satisfied.
        #[link_section = ".init.text"]
        pub unsafe fn register(&mut self, _init_ctx: InitContextRef<'_>) -> Result {
            let hooks_ptr = self.hook_list.as_mut_ptr();
            let hooks_len = self.hook_list.len() as c_int;
            let name_ptr = self.lsm_name.as_char_ptr();
            // SAFETY: FFI call, internal refs are 'static so pointers will remain valid.
            // No race conditions assuming specified preconditions hold
            unsafe {
                security_add_hooks(hooks_ptr, hooks_len, name_ptr as *mut c_char);
            }

            return Ok(());
        }
    }

    /// Linux security module subsystem hook functions
    ///
    /// This trait can be implemented to define the hook functions
    /// required for a security module. The registration of these
    /// hooks is usually facilated by the `define_lsm` macro, which
    /// takes a type implementing this trait as an argument.
    pub trait SecurityHooks {
        fn ptrace_access_check(_child: TaskStructRef<'_>, _mode: c_uint) -> Result {
            return Ok(());
        }

        fn ptrace_traceme(_parent: TaskStructRef<'_>) -> Result {
            return Ok(());
        }

        fn task_free(_task: TaskStructRef<'_>) {
            return;
        }

        fn task_prctl(
            _option: c_int,
            _arg2: c_ulong,
            _arg3: c_ulong,
            _arg4: c_ulong,
            _arg5: c_ulong,
        ) -> Result {
            return Ok(());
        }
    }

    /// A generic struct containing wrapper `extern "C"` functions for
    /// each security subsystem hook.
    ///
    /// These wrapper functions will call the corresponding high-level
    /// hook methods implemented in the `SecurityHooks` trait for the
    /// type paramter `T`, and handle converting arguments and return
    /// values between those required by the kernel's C interface and
    /// those used by the abstractions in the `SecurityHooks` trait.
    ///
    /// This type should not usually be used directly, but it is used by
    /// the `define_lsm` macro.
    pub struct __SecurityHooks<T: SecurityHooks> {
        // enable use of type paramter
        _phantom: PhantomData<T>,
    }

    impl<T: SecurityHooks> __SecurityHooks<T> {
        pub unsafe extern "C" fn ptrace_access_check(
            child: *mut task_struct,
            mode: c_uint,
        ) -> c_int {
            let child = unsafe { TaskStructRef::from_ptr(&child).unwrap() };
            match T::ptrace_access_check(child, mode) {
                Ok(_) => {
                    return 0;
                }
                Err(e) => {
                    return e.to_kernel_errno();
                }
            }
        }

        pub unsafe extern "C" fn ptrace_traceme(parent: *mut task_struct) -> c_int {
            let parent = unsafe { TaskStructRef::from_ptr(&parent).unwrap() };
            match T::ptrace_traceme(parent) {
                Ok(_) => {
                    return 0;
                }
                Err(e) => {
                    return e.to_kernel_errno();
                }
            }
        }

        pub unsafe extern "C" fn task_free(task: *mut task_struct) {
            let task = unsafe { TaskStructRef::from_ptr(&task).unwrap() };
            T::task_free(task);
        }

        pub unsafe extern "C" fn task_prctl(
            option: c_int,
            arg2: c_ulong,
            arg3: c_ulong,
            arg4: c_ulong,
            arg5: c_ulong,
        ) -> c_int {
            match T::task_prctl(option, arg2, arg3, arg4, arg5) {
                Ok(_) => {
                    return 0;
                }
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
            return DefineLSMTraitBoundCheck {
                _phantom: PhantomData,
            };
        }
    }

    // https://stackoverflow.com/questions/34304593/counting-length-of-repetition-in-macro
    #[macro_export]
    macro_rules! count {
        () => (0usize);
        ( $x:tt $($xs:tt)* ) => (1usize + kernel::count!($($xs)*));
    }

    #[macro_export]
    macro_rules! define_lsm {
        ( $name:literal, $a:ty, $( $x:ident ),+ ) => {

            // generates a clear error if trait bounds are not satisfied for $a
            static __define_lsm_trait_bound_check: DefineLSMTraitBoundCheck<$a> = DefineLSMTraitBoundCheck::new();

            // variable (not constant) containing LSM name as required by C interfaces
            static __LSM_NAME: &'static $crate::str::CStr = $crate::c_str!($name);

            // log prefix for kernel print
            const __LOG_PREFIX: &[u8] = $crate::c_str!($name).as_bytes_with_nul();

            const i: usize = kernel::count!($($x)*);

            // the raw list of security hooks
            static mut __lsm_hooks_raw: [security_hook_list; i] = [
                $(
                    security_hook_list {
                        // hook location: bprm_check_security
                        // SAFETY: pointer to be used in C, *mut required
                        head: unsafe { &security_hook_heads.$x as *const _ as *mut _ },
                        // hook function itself
                        hook: security_list_options {
                            $x: Some(__SecurityHooks::<$a>::$x),
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

            // the security hooks struct which stores a reference to the raw array above
            static mut __lsm_hooks: SecurityHookList = SecurityHookList::new(
                __LSM_NAME,
                // SAFETY: __lsm_hooks_raw should only be accessed here
                unsafe { &mut __lsm_hooks_raw },
            );

            //  LSM initialization function, stored in init section
            #[link_section = ".init.text"]
            unsafe extern "C" fn __lsm_init_fn() -> c_int {
                let init_ctx = unsafe { InitContext::new() };
                let ret = unsafe { <$a>::init(&mut __lsm_hooks, init_ctx.get_ref()) };
                match ret {
                    Ok(_) => {
                        return 0;
                    },
                    Err(e) => {
                        return e.to_kernel_errno();
                    }
                }
            }

            /// The `lsm_info` struct required to register the LSM with the kernel
            /// 
            /// This struct is placed in the `.lsm_info.init` section, and must be
            /// `pub` or `#[no_mangle] to function correctly
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
}

pub mod rcu {

    use crate::bindings::*;
    use crate::c_types::*;
    use core::marker::PhantomData;

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
            RCULockContext { _private: () }
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
        _phantom: PhantomData<&'a RCULockContext>,
    }

    pub fn with_rcu_read_lock<T, F: FnOnce(RCULockContextRef<'_>) -> T>(f: F) -> T {
        let ctx = RCULockContext::lock();
        f(ctx.get_ref())
    }

    pub fn rcu_dereference<T>(p: *mut *mut T, _ctx: RCULockContextRef<'_>) -> *mut T {
        unsafe { rcu_dereference_exported(p as *mut *mut c_void) as *mut T }
    }

    pub fn rcu_dereference_const<T>(p: *const *const T, _ctx: RCULockContextRef<'_>) -> *const T {
        unsafe { rcu_dereference_exported(p as *mut *mut c_void) as *const T }
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
            let rcu_head_ptr = unsafe { (*p).get_rcu_head() };
            // get offset of RCU head
            let rcu_head_offset = (rcu_head_ptr as u64) - (p as u64);
            // convert offset to function pointer type as required by C interface
            let callback: rcu_callback_t = unsafe { Some(core::mem::transmute(rcu_head_offset)) };
            unsafe {
                // set callback to free memory
                call_rcu(rcu_head_ptr, callback);
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

    pub mod rcu_list {

        use crate::yama_rust_interfaces::rcu::*;
        use alloc::boxed::Box;
        use core::cell::UnsafeCell;
        use core::marker::PhantomData;
        use core::ptr::NonNull;

        pub struct RCUListEntry<T> {
            next: *mut T,
            prev: *mut T,
        }

        pub struct RCULinks<T> {
            entry: UnsafeCell<RCUListEntry<T>>,
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
                let ptr_to_list_entry = self.entry.get();
                let ptr_to_next_ptr = unsafe { &mut (*ptr_to_list_entry).next as *mut *mut T };
                rcu_dereference(ptr_to_next_ptr, ctx)
            }

            // atomically assign the given pointer as the pointer to the next element
            pub fn rcu_assign_next(&self, next: *mut T, ctx: RCULockContextRef<'_>) {
                let ptr_to_list_entry = self.entry.get();
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

            pub fn cursor_front_rcu<'a, 'b>(&'a self, ctx: RCULockContextRef<'b>) -> RCUListCursor<'a, 'b, T> {
                RCUListCursor {
                    cur: NonNull::new(rcu_dereference(
                        &self.head as *const *mut T::EntryType as *mut *mut T::EntryType,
                        ctx,
                    )),
                    _rcu_ctx: PhantomData,
                    _list: PhantomData,
                }
            }

            pub fn cursor_front_mut_rcu<'a, 'b>(
                &'a mut self,
                ctx: RCULockContextRef<'b>,
            ) -> RCUListCursorMut<'a, 'b, T> {
                RCUListCursorMut {
                    cur: NonNull::new(rcu_dereference(
                        &mut self.head as *mut *mut T::EntryType,
                        ctx,
                    )),
                    list: self,
                    _rcu_ctx: PhantomData,
                }
            }

            pub fn cursor_front_inplace_mut_rcu<'a, 'b>(
                &'a self,
                ctx: RCULockContextRef<'b>,
            ) -> RCUListCursorInplaceMut<'a, 'b, T> {
                RCUListCursorInplaceMut {
                    cur: NonNull::new(rcu_dereference(
                        &self.head as *const *mut T::EntryType as *mut *mut T::EntryType,
                        ctx,
                    )),
                    _rcu_ctx: PhantomData,
                    _list: PhantomData,
                }
            }

            pub fn push_back_rcu(&mut self, new: Box<T::EntryType>, ctx: RCULockContextRef<'_>) {
                // get head ptr
                let head = NonNull::new(self.head);
                // convert box to raw pointer to prevent drop
                let ptr_to_new_item = Box::into_raw(new);
                // get list entry for new item
                let ptr_to_new_list_entry =
                    unsafe { T::get_links(&mut *ptr_to_new_item).entry.get() };

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

                            // set prev and next ptrs for current item
                            (*ptr_to_new_list_entry).prev = ptr_to_tail_item;
                            (*ptr_to_new_list_entry).next = core::ptr::null_mut();

                            // rcu_assign to the tail item's next pointer
                            tail_links.rcu_assign_next(ptr_to_new_item, ctx);

                            // update head's prev pointer
                            (*ptr_to_head_list_entry).prev = ptr_to_new_item;
                        }
                    }
                    // if list is empty
                    None => {
                        unsafe {
                            // set up next pointer to be null
                            (*ptr_to_new_list_entry).next = core::ptr::null_mut();
                            // set up prev pointer to point to itself (tail)
                            (*ptr_to_new_list_entry).prev = ptr_to_new_item;
                            // rcu_assign to the list's head pointer
                            rcu_assign_pointer(
                                &mut self.head as *mut *mut T::EntryType,
                                ptr_to_new_item,
                                ctx,
                            );
                        }
                    }
                }
            }
        }

        pub struct RCUListCursor<'a, 'b, T: RCUGetLinks + GetRCUHead> {
            cur: Option<NonNull<T::EntryType>>,
            _list: PhantomData<&'a ()>,
            _rcu_ctx: PhantomData<&'b ()>,
        }

        impl<'a, 'b, T: RCUGetLinks + GetRCUHead> RCUListCursor<'a, 'b, T> {
            pub fn current(&self) -> Option<&T::EntryType> {
                Some(unsafe { &*self.cur?.as_ptr() })
            }

            pub fn move_next_rcu(&mut self, ctx: RCULockContextRef<'_>) {
                if let Some(p) = self.cur {
                    let next_ptr =
                        unsafe { T::get_links(&mut *p.as_ptr()).rcu_dereference_next(ctx) };
                    self.cur = NonNull::new(next_ptr);
                }
            }
        }

        pub struct RCUListCursorInplaceMut<'a, 'b, T: RCUGetLinks + GetRCUHead> {
            cur: Option<NonNull<T::EntryType>>,
            _list: PhantomData<&'a ()>,
            _rcu_ctx: PhantomData<&'b ()>,
        }

        impl<'a, 'b, T: RCUGetLinks + GetRCUHead> RCUListCursorInplaceMut<'a, 'b, T> {
            pub fn current_mut(&mut self) -> Option<*mut T::EntryType> {
                Some(self.cur?.as_ptr())
            }

            pub fn move_next_rcu(&mut self, ctx: RCULockContextRef<'_>) {
                if let Some(p) = self.cur {
                    let next_ptr =
                        unsafe { T::get_links(&mut *p.as_ptr()).rcu_dereference_next(ctx) };
                    self.cur = NonNull::new(next_ptr);
                }
            }
        }

        pub struct RCUListCursorMut<'a, 'b, T: RCUGetLinks + GetRCUHead> {
            cur: Option<NonNull<T::EntryType>>,
            list: &'a mut RCUList<T>,
            _rcu_ctx: PhantomData<&'b ()>,
        }

        impl<'a, 'b, T: RCUGetLinks + GetRCUHead> RCUListCursorMut<'a, 'b, T> {
            pub fn current(&self) -> Option<&T::EntryType> {
                Some(unsafe { &*self.cur?.as_ptr() })
            }

            pub fn move_next_rcu(&mut self, ctx: RCULockContextRef<'_>) {
                if let Some(p) = self.cur {
                    let next_ptr =
                        unsafe { T::get_links(&mut *p.as_ptr()).rcu_dereference_next(ctx) };
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
                            let ptr_to_next_list_entry =
                                T::get_links(&mut *ptr_to_next_item).entry.get();
                            // update prev pointer for next item
                            (*ptr_to_next_list_entry).prev = ptr_to_prev_item;
                        }

                        // if this item is the list head, i.e. prev points to tail
                        if p.as_ptr() == self.list.head {
                            // rcu_assign the list's head pointer
                            rcu_assign_pointer(
                                &mut self.list.head as *mut *mut T::EntryType,
                                ptr_to_next_item,
                                ctx,
                            );
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

            pub fn replace_current_rcu(
                &mut self,
                new: Box<T::EntryType>,
                ctx: RCULockContextRef<'_>,
            ) {
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
                            rcu_assign_pointer(
                                &mut self.list.head as *mut *mut T::EntryType,
                                ptr_to_new_item,
                                ctx,
                            );
                        } else {
                            // get previous item's links
                            let prev_list_links = T::get_links(&mut *ptr_to_prev_item);
                            // rcu-assign next pointer for prev item
                            prev_list_links.rcu_assign_next(ptr_to_new_item, ctx);
                        }

                        // set prev pointer for next item
                        if ptr_to_next_item != core::ptr::null_mut() {
                            let ptr_to_next_entry =
                                T::get_links(&mut *ptr_to_next_item).entry.get();
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
    }
}

pub mod task {

    use crate::bindings::*;
    use crate::yama_rust_interfaces::rcu::rcu_dereference;
    use crate::yama_rust_interfaces::rcu::rcu_dereference_const;
    use crate::yama_rust_interfaces::rcu::with_rcu_read_lock;
    use crate::yama_rust_interfaces::rcu::RCULockContextRef;
    use core::convert::TryInto;
    use core::marker::PhantomData;
    use core::ptr::NonNull;

    pub struct TaskStruct {
        ptr: NonNull<task_struct>,
    }

    impl TaskStruct {
        pub(crate) fn from_ptr(ptr: *mut task_struct) -> Option<TaskStruct> {
            match NonNull::new(ptr) {
                Some(p) => {
                    // increment reference count
                    unsafe {
                        get_task_struct_exported(ptr);
                    }
                    Some(TaskStruct { ptr: p })
                }
                None => None,
            }
        }

        pub(crate) fn from_nonnull(ptr: NonNull<task_struct>) -> TaskStruct {
            unsafe {
                get_task_struct_exported(ptr.as_ptr());
            }
            TaskStruct { ptr }
        }

        pub fn from_pid(pid: pid_t) -> Option<TaskStruct> {
            let ptr = unsafe { find_get_task_by_vpid(pid) };
            TaskStruct::from_ptr(ptr)
        }

        pub fn current() -> Option<TaskStruct> {
            let ptr = unsafe { get_current_exported() };
            TaskStruct::from_ptr(ptr)
        }

        pub fn get_ref<'a>(&'a self) -> TaskStructRef<'a> {
            TaskStructRef {
                ptr: self.ptr,
                _marker: PhantomData,
            }
        }
    }

    impl Drop for TaskStruct {
        fn drop(&mut self) {
            unsafe {
                put_task_struct_exported(self.ptr.as_ptr());
            }
        }
    }

    #[derive(Copy, Clone)]
    pub struct TaskStructRef<'a> {
        ptr: NonNull<task_struct>,
        _marker: PhantomData<&'a TaskStruct>,
    }

    impl<'a> PartialEq for TaskStructRef<'a> {
        fn eq(&self, other: &Self) -> bool {
            self.ptr == other.ptr
        }
    }

    impl<'a> TaskStructRef<'a> {
        pub(crate) unsafe fn from_ptr<'b>(ptr: &'b *mut task_struct) -> Option<TaskStructRef<'b>> {
            match NonNull::new(*ptr) {
                Some(p) => Some(TaskStructRef {
                    ptr: p,
                    _marker: PhantomData,
                }),
                None => None,
            }
        }

        pub fn get_task_struct(&self) -> TaskStruct {
            TaskStruct::from_nonnull(self.ptr)
        }

        pub fn pid(&self) -> pid_t {
            unsafe { (*self.ptr.as_ptr()).pid }
        }

        pub fn same_thread_group(&self, other: TaskStructRef<'_>) -> bool {
            unsafe { (*self.ptr.as_ptr()).signal == (*other.ptr.as_ptr()).signal }
        }

        pub fn thread_group_leader(&self) -> bool {
            unsafe { (*self.ptr.as_ptr()).exit_signal >= 0 }
        }

        pub fn pid_alive(&self) -> bool {
            unsafe { (*self.ptr.as_ptr()).thread_pid != core::ptr::null_mut() }
        }

        pub fn flags_set(&self, flags: u32) -> bool {
            unsafe { (*self.ptr.as_ptr()).flags & flags != 0 }
        }

        pub fn get_thread_group_leader<'b>(
            &'a self,
            ctx: RCULockContextRef<'a>,
        ) -> Option<TaskStructRef<'b>> {
            let ptr = unsafe {
                rcu_dereference(&mut (*self.ptr.as_ptr()).group_leader as *mut *mut _, ctx)
            };
            match NonNull::new(ptr) {
                Some(p) => Some(TaskStructRef {
                    ptr: p,
                    _marker: PhantomData,
                }),
                None => None,
            }
        }

        pub fn get_real_parent<'b>(
            &'a self,
            ctx: RCULockContextRef<'b>,
        ) -> Option<TaskStructRef<'b>> {
            let ptr = unsafe {
                rcu_dereference(&mut (*self.ptr.as_ptr()).real_parent as *mut *mut _, ctx)
            };
            match NonNull::new(ptr) {
                Some(p) => Some(TaskStructRef {
                    ptr: p,
                    _marker: PhantomData,
                }),
                None => None,
            }
        }

        pub fn get_ptrace_parent<'b>(
            &'a self,
            ctx: RCULockContextRef<'b>,
        ) -> Option<TaskStructRef<'b>> {
            let ptr =
                unsafe { rcu_dereference(&mut (*self.ptr.as_ptr()).parent as *mut *mut _, ctx) };
            match NonNull::new(ptr) {
                Some(p) => Some(TaskStructRef {
                    ptr: p,
                    _marker: PhantomData,
                }),
                None => None,
            }
        }

        pub fn current_ns_capable(&self, cap: u32, ctx: RCULockContextRef<'_>) -> bool {
            let task_cred = unsafe {
                rcu_dereference_const(&(*self.ptr.as_ptr()).real_cred as *const *const cred, ctx)
            };
            unsafe { ns_capable_exported((*task_cred).user_ns, cap.try_into().unwrap()) >= 0 }
        }

        pub fn has_ns_capability_current(&self, cap: u32) -> bool {
            unsafe {
                has_ns_capability(
                    self.ptr.as_ptr(),
                    current_user_ns_exported(),
                    cap.try_into().unwrap(),
                )
            }
        }

        pub fn is_descendant(&self, child: TaskStructRef<'_>) -> bool {
            with_rcu_read_lock(|ctx| {
                let parent = if self.thread_group_leader() {
                    *self
                } else {
                    self.get_thread_group_leader(ctx).unwrap()
                };
                let mut walker = child;

                while walker.pid() > 0 {
                    walker = if walker.thread_group_leader() {
                        walker
                    } else {
                        walker.get_thread_group_leader(ctx).unwrap()
                    };
                    if walker == parent {
                        return true;
                    }
                    walker = walker.get_real_parent(ctx).unwrap();
                }
                return false;
            })
        }
    }

    pub fn current_capable(cap: i32) -> bool {
        unsafe { capable_exported(cap) }
    }
}

pub mod work_queue {

    use crate::bindings::*;
    use crate::container_of;
    use crate::prelude::*;
    use crate::yama_rust_interfaces::init_context::*;
    use alloc::boxed::Box;
    use core::marker::PhantomData;

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
    }

    impl<T: StaticWorkFunc> StaticWorkStruct<T> {
        pub const fn new() -> StaticWorkStruct<T> {
            StaticWorkStruct {
                work: InitCell::new(None),
                _marker: PhantomData,
            }
        }

        #[link_section = ".init.text"]
        pub unsafe fn init(&'static self, init_ctx: InitContextRef<'_>) {
            // SAFETY: mutating data is safe during init phase
            unsafe {
                *self.work.get(init_ctx) = Some(work_struct {
                    data: atomic_long_t {
                        counter: (WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC),
                    },
                    entry: list_head {
                        next: core::ptr::null_mut(),
                        prev: core::ptr::null_mut(),
                    },
                    func: Some(StaticWorkFuncCInterface::<T>::work_func),
                });
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

    unsafe impl<T: StaticWorkFunc> Sync for StaticWorkStruct<T> {}

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
                Box::from_raw(container_of!(work, DynamicWorkPayload<T, U>, work_head)
                    as *mut DynamicWorkPayload<T, U>)
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
                    func: Some(DynamicWorkFuncCInterface::<T, U>::work_func),
                },
                _marker: PhantomData,
            })
            .unwrap();
            // covert to raw pointer to prevent drop
            let payload = Box::into_raw(payload);

            let current = unsafe { get_current_exported() };

            let ret = unsafe {
                task_work_add(
                    current,
                    &(*payload).work_head as *const _ as *mut _,
                    task_work_notify_mode_TWA_RESUME,
                )
            };
            pr_info!("Task work add: {}\n", ret);
        }
    }
}

pub mod sysctl {

    use crate::bindings::*;
    use crate::c_types::*;
    use crate::prelude::*;
    use crate::str::CStr;
    use crate::yama_rust_interfaces::init_context::{InitCell, InitContextRef};
    use core::marker::PhantomData;

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
        pub(crate) unsafe extern "C" fn dointvec_minmax(
            table: *mut ctl_table,
            write: c_int,
            buffer: *mut c_void,
            lenp: *mut c_size_t,
            ppos: *mut loff_t,
        ) -> c_int {
            let mut table_copy = unsafe { *table };

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
        pub const fn new(
            default: c_int,
            min: c_int,
            max: c_int,
            path: &'static [ctl_path],
        ) -> SysctlInt<T> {
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
        pub unsafe fn init(
            &'static self,
            name: &'static CStr,
            mode: u16,
            init_ctx: InitContextRef<'_>,
        ) {
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
                    register_sysctl_paths(
                        self.sysctl_path.as_ptr() as *const _,
                        t as *const _ as *mut _,
                    )
                };
                let a = sret != core::ptr::null_mut();
                pr_info!("Registering sysctl paths: {}\n", a);
            }
        }
    }

    unsafe impl<T: SysctlIntHooks> Sync for SysctlInt<T> {}
}

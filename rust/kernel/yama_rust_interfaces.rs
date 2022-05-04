//! Interfaces required for the Rust port of Yama
//!
//! These comprise all new interfaces created to support
//! the Rust port of Yama. With further development, these
//! modules would be moved to more suitable locations
//! within the kernel crate

/// Compile-time verification of context
pub mod context {

    use core::marker::PhantomData;

    /// RAII type representing init context
    ///
    /// A valid instance of this struct indicates that execution
    /// is still in the init phase.
    pub struct InitContext {
        // prevents direct construction
        _private: (),
    }

    impl InitContext {
        /// Returns a new `InitContext`
        ///
        /// # Safety
        ///
        /// The caller is responsible for ensuring instances
        /// of this struct do not outlive the init phase.
        #[link_section = ".init.text"]
        #[inline]
        pub const unsafe fn new() -> InitContext {
            InitContext { _private: () }
        }

        /// Returns a zero-sized 'reference' to the `InitContext` instance
        ///
        /// These 'references' can be freely copied and passed around as
        /// arguments, and the compiler will ensure they do not outlive the
        ///  `InitContext` they refer to
        #[inline]
        pub const fn get_ref<'a>(&'a self) -> InitContextRef<'a> {
            InitContextRef {
                _marker: PhantomData,
            }
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
        // zero-sized phantom 'reference'
        _marker: PhantomData<&'a InitContext>,
    }

    /// RAII type representing the context of a specific event,
    /// such as a system call or security hook, run for a specific
    /// userspace process
    pub struct EventContext {
        _private: (),
    }

    impl EventContext {
        /// Returns a new `EventContext`
        ///
        /// # Safety
        ///
        /// Returned instances must not outlive the relevant event
        #[inline]
        pub const unsafe fn new() -> Self {
            Self { _private: () }
        }

        /// Returns a zero-sized, borrow-checker-enforced 'reference'
        /// to the `EventContext` instance
        #[inline]
        pub const fn get_ref<'a>(&'a self) -> EventContextRef<'a> {
            EventContextRef {
                _marker: PhantomData,
            }
        }
    }

    /// A zero-sized, borrow-checker-enforced 'reference'
    /// to an `EventContext` instance. Can only be created
    /// by calling `get_ref` on an `EventContext`
    #[derive(Copy, Clone)]
    pub struct EventContextRef<'a> {
        // zero-sized phantom 'reference'
        _marker: PhantomData<&'a EventContext>,
    }
}

/// Abstractions for Linux security module subsystem functionality
///
/// This includes the necessary interfaces for initializing
/// a security module and creating security subsystem hooks
pub mod security_module {

    use crate::bindings::*;
    use crate::c_types::*;
    use crate::prelude::*;
    use crate::str::CStr;
    use crate::yama_rust_interfaces::context::*;
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
            SecurityHookList {
                lsm_name,
                hook_list,
            }
        }

        /// Registers the list of security hooks
        ///
        ///
        /// # Arguments
        ///
        /// * _init_ctx: An `InitContextRef` to confirm execution is in
        /// the intiialization phase.
        ///
        #[link_section = ".init.text"]
        pub fn register(&'static mut self, _init_ctx: InitContextRef<'_>) {
            let hooks_ptr = self.hook_list.as_mut_ptr();
            let hooks_len = self.hook_list.len() as c_int;
            let name_ptr = self.lsm_name.as_char_ptr();
            // SAFETY: passed pointers are derived from valid 'static refs
            // which will continue to be held for 'static lifetime of self
            // and len value is correctly derived using slice len() method
            unsafe {
                security_add_hooks(hooks_ptr, hooks_len, name_ptr as *mut c_char);
            }
        }
    }

    /// A generic struct containing wrapper `extern "C"` functions for
    /// each security subsystem hook.
    ///
    /// These wrapper functions call the corresponding high-level
    /// hook methods implemented in the `SecurityModule` trait for the
    /// type paramter `T`, and handle converting arguments and return
    /// values between those required by the kernel's C interface and
    /// those used by the abstractions in the `SecurityModule` trait.
    ///
    /// This type should not usually be used directly, but it is used by
    /// the `define_lsm` macro.
    pub struct SecurityHooks<T: SecurityModule> {
        // enable use of type paramter
        _phantom: PhantomData<T>,
    }

    impl<T: SecurityModule> SecurityHooks<T> {
        /// C-compatible wrapper template for `ptrace_access_check` hook
        pub unsafe extern "C" fn ptrace_access_check(
            child: *mut task_struct,
            mode: c_uint,
        ) -> c_int {
            // let a = unsafe { ktime_get() };
            // SAFETY: event_ctx is local and will not outlive security hook call
            let event_ctx = unsafe { EventContext::new() };
            // SAFETY: pointer passed by kernel should remain valid
            let child = unsafe { TaskStructRef::from_ptr(child, event_ctx.get_ref()).unwrap() };
            match T::ptrace_access_check(child, mode, event_ctx.get_ref()) {
                Ok(_) => 0,
                Err(e) => e.to_kernel_errno(),
            }
            // let b = unsafe { ktime_get() };
            // pr_info!("ptrace_access_check time: {}\n", b-a);
            // ret
        }

        /// C-compatible wrapper template for `ptrace_traceme` hook
        pub unsafe extern "C" fn ptrace_traceme(parent: *mut task_struct) -> c_int {
            // SAFETY: event_ctx is local and will not outlive security hook call
            let event_ctx = unsafe { EventContext::new() };
            // SAFETY: pointer passed by kernel should remain valid
            let parent = unsafe { TaskStructRef::from_ptr(parent, event_ctx.get_ref()).unwrap() };
            match T::ptrace_traceme(parent, event_ctx.get_ref()) {
                Ok(_) => 0,
                Err(e) => e.to_kernel_errno(),
            }
        }

        /// C-compatible wrapper template for `task_free` hook
        pub unsafe extern "C" fn task_free(task: *mut task_struct) {
            // SAFETY: event_ctx is local and will not outlive security hook call
            let event_ctx = unsafe { EventContext::new() };
            // SAFETY: pointer passed by kernel should remain valid
            let task = unsafe { TaskStructRef::from_ptr(task, event_ctx.get_ref()).unwrap() };
            T::task_free(task, event_ctx.get_ref());
        }

        /// C-compatible wrapper template for `task_prctl` hook
        pub unsafe extern "C" fn task_prctl(
            option: c_int,
            arg2: c_ulong,
            arg3: c_ulong,
            arg4: c_ulong,
            arg5: c_ulong,
        ) -> c_int {
            // let a = unsafe { ktime_get() };
            // SAFETY: event_ctx is local and will not outlive security hook call
            let event_ctx = unsafe { EventContext::new() };
            match T::task_prctl(option, arg2, arg3, arg4, arg5, event_ctx.get_ref()) {
                Ok(_) => 0,
                Err(e) => e.to_kernel_errno(),
            }
            // let b = unsafe { ktime_get() };
            // pr_info!("prctl time: {}\n", b-a);
            // ret
        }
    }

    /// A trait representing a security module through the implementation
    /// of an initialization function and one or more security hooks
    pub trait SecurityModule {
        /// Initializes the security module
        ///
        /// # Arguments
        ///
        /// * `hooks`: a `SecurityHookList` representing the module's security hooks
        /// * `init_ctx`: an `InitContextRef` ensuring execution is in init phase
        fn init(hooks: &'static mut SecurityHookList, init_ctx: InitContextRef<'_>) -> Result;

        /// `ptrace_access_check` security hook
        fn ptrace_access_check(
            _child: TaskStructRef<'_>,
            _mode: u32,
            _event_ctx: EventContextRef<'_>,
        ) -> Result {
            Ok(())
        }

        /// `ptrace_traceme` security hook
        fn ptrace_traceme(_parent: TaskStructRef<'_>, _event_ctx: EventContextRef<'_>) -> Result {
            Ok(())
        }

        /// `task_free` security hook
        fn task_free(_task: TaskStructRef<'_>, _event_ctx: EventContextRef<'_>) {}

        /// `task_prctl` security hook
        fn task_prctl(
            _option: c_int,
            _arg2: c_ulong,
            _arg3: c_ulong,
            _arg4: c_ulong,
            _arg5: c_ulong,
            _event_ctx: EventContextRef<'_>,
        ) -> Result {
            Ok(())
        }
    }

    /// Counts the number of arguments given Based on: https://stackoverflow.com/
    /// questions/34304593/counting-length-of-repetition-in-macro
    #[macro_export]
    macro_rules! count {
        () => (0usize);
        ( $x:tt $($xs:tt)* ) => (1usize + kernel::count!($($xs)*));
    }

    /// Expands to define the necessary static structures and functions
    /// to register the desired security module functionality
    #[macro_export]
    macro_rules! define_lsm {
        ( $name:literal, $security_module:ty, $( $security_hook:ident ),+ ) => {
            // generates a clear error if trait bounds are not satisfied for $a
            struct DefineLSMTraitBoundCheck<T: SecurityModule> {
                _marker: core::marker::PhantomData<T>,
            }
            static __define_lsm_trait_bound_check: DefineLSMTraitBoundCheck<$security_module> =
                DefineLSMTraitBoundCheck { _marker: core::marker::PhantomData };

            // variable (not constant) containing LSM name as required by C interfaces
            static __LSM_NAME: &'static $crate::str::CStr = $crate::c_str!($name);

            // log prefix for kernel print
            const __LOG_PREFIX: &[u8] = $crate::c_str!($name).as_bytes_with_nul();

            const __lsm_hook_count: usize = kernel::count!($($security_hook)*);

            // the raw list of security hooks
            static mut __lsm_hooks_raw: [security_hook_list; __lsm_hook_count] = [
                $(
                    security_hook_list {
                        // SAFETY: security_hook_heads is not accessed, address of field taken
                        head: unsafe { &security_hook_heads.$security_hook as *const _ as *mut _ },
                        hook: security_list_options {
                            $security_hook: Some(SecurityHooks::<$security_module>::$security_hook),
                        },
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
                // SAFETY: LSM init function is only called during init
                let init_ctx = unsafe { InitContext::new() };
                // SAFETY: __lsm_hooks is only accessed here, and this function
                // will only be called once, never concurrently
                let __lsm_hooks_ref = unsafe { &mut __lsm_hooks };
                let ret = <$security_module>::init(__lsm_hooks_ref, init_ctx.get_ref());
                match ret {
                    Ok(_) => {
                        0
                    },
                    Err(e) => {
                        e.to_kernel_errno()
                    }
                }
            }

            /// The `lsm_info` struct required to register the LSM with the kernel
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

/// RCU synchronization functionality
pub mod rcu {

    use crate::bindings::*;
    use crate::c_types::*;
    use core::marker::PhantomData;

    /// RAII type representing a held RCU read lock /
    /// RCU critical section
    pub struct RCUReadLock {
        // private field prevents direct construction
        _private: (),
    }

    impl RCUReadLock {
        /// Acquires the RCU read lock and returns a new instance
        #[inline]
        pub fn lock() -> RCUReadLock {
            // SAFETY: FFI call
            unsafe {
                rcu_read_lock_exported();
            }
            RCUReadLock { _private: () }
        }

        /// Returns a zero-sized, borrow-checker-enforced 'reference'
        /// to the instance
        #[inline]
        pub const fn get_ref<'a>(&'a self) -> RCUReadLockRef<'a> {
            RCUReadLockRef {
                _phantom: PhantomData,
            }
        }
    }

    impl Drop for RCUReadLock {
        #[inline]
        fn drop(&mut self) {
            // SAFETY: FFI call
            unsafe {
                rcu_read_unlock_exported();
            }
        }
    }

    /// A zero-sized, borrow-checker-enforced 'reference' to an
    /// `RCUReadLock` instance
    #[derive(Copy, Clone)]
    pub struct RCUReadLockRef<'a> {
        // zero-sized phantom 'reference'
        _phantom: PhantomData<&'a RCUReadLock>,
    }

    /// Calls the given closure within an RCU critical section
    #[inline]
    pub fn with_rcu_read_lock<T, F: FnOnce(RCUReadLockRef<'_>) -> T>(f: F) -> T {
        let ctx = RCUReadLock::lock();
        f(ctx.get_ref())
    }

    /// Safely fetches an RCU pointer for dereferencing
    ///
    /// # Safety
    ///
    /// `p` must be a valid, safe-to-read pointer to an RCU pointer
    #[inline]
    pub(crate) unsafe fn rcu_dereference<T>(p: *mut *mut T, _ctx: RCUReadLockRef<'_>) -> *mut T {
        // SAFETY: p should be valid, safe-to-read pointer to RCU pointer
        unsafe { rcu_dereference_exported(p as *mut *mut c_void) as *mut T }
    }

    /// Safely fetches a `const` RCU pointer for dereferencing
    ///
    /// # Safety
    ///
    /// `p` must be a valid, safe-to-read pointer to an RCU pointer
    #[inline]
    pub(crate) unsafe fn rcu_dereference_const<T>(
        p: *const *const T,
        _ctx: RCUReadLockRef<'_>,
    ) -> *const T {
        // SAFETY: p should be valid, safe-to-read pointer to RCU pointer
        unsafe { rcu_dereference_exported(p as *mut *mut c_void) as *const T }
    }

    /// Safely assigns to an RCU pointer
    ///
    /// # Safety
    ///
    /// `p` must be a valid, safe-to-write pointer to an RCU pointer
    #[inline]
    pub(crate) unsafe fn rcu_assign_pointer<T>(
        p: *mut *mut T,
        v: *mut T,
        _ctx: RCUReadLockRef<'_>,
    ) {
        // SAFETY: p should be valid, safe-to-write pointer to RCU pointer
        unsafe {
            rcu_assign_pointer_exported(p as *mut *mut c_void, v as *mut c_void);
        }
    }

    /// Frees the given RCU-protected item
    ///
    /// # Safety
    ///
    /// `p` must be a valid RCU heap pointer not being concurrently mutably accessed
    pub(crate) unsafe fn rcu_free<T: GetRCUHead>(p: *mut T, _ctx: RCUReadLockRef<'_>) {
        // SAFETY: p should be a valid, safe-to-mutably-access RCU pointer
        let rcu_head_ptr = unsafe { (*p).get_rcu_head() as *const _ as *mut _ };
        // get offset of RCU head
        let rcu_head_offset = (rcu_head_ptr as usize) - (p as usize);
        // SAFETY: kvfree_call_rcu requires offset as type rcu_callback_t
        let callback: rcu_callback_t = unsafe { Some(core::mem::transmute(rcu_head_offset)) };
        // SAFETY: callback is offset of *rcu_head_ptr in *p
        unsafe {
            kvfree_call_rcu(rcu_head_ptr, callback);
        }
    }

    /// Newtype wrapper around a callback_head
    #[repr(transparent)]
    pub struct RCUHead(callback_head);

    impl RCUHead {
        /// Initializes a null `RCUHead`
        #[inline]
        pub const fn new() -> RCUHead {
            RCUHead(callback_head {
                next: core::ptr::null_mut(),
                func: None,
            })
        }
    }

    /// Allows retrieving an `RCUHead field`
    pub trait GetRCUHead {
        /// retrieves an `RCUHead` field from `self`
        fn get_rcu_head(&self) -> &RCUHead;
    }

    /// RCU-protected linked list functionality
    pub mod rcu_list {

        use crate::yama_rust_interfaces::rcu::*;
        use alloc::boxed::Box;
        use core::cell::UnsafeCell;
        use core::marker::PhantomData;
        use core::ptr::NonNull;

        /// Link pointers for an RCU list entry
        ///
        /// # Invariants
        ///
        /// `next` and `prev` will always be either null or valid RCU pointers
        pub struct RCUListEntry<T> {
            next: *mut T,
            prev: *mut T,
        }

        /// An RCU list entry to be embedded in a list node type
        pub struct RCULinks<T> {
            entry: UnsafeCell<RCUListEntry<T>>,
        }

        impl<T> RCULinks<T> {
            /// Initialize a null `RCULinks`
            #[inline]
            pub fn new() -> RCULinks<T> {
                RCULinks {
                    entry: UnsafeCell::new(RCUListEntry {
                        next: core::ptr::null_mut(),
                        prev: core::ptr::null_mut(),
                    }),
                }
            }

            /// RCU-dereferences and returns the pointer to the next element
            #[inline]
            pub(crate) fn rcu_dereference_next(&self, ctx: RCUReadLockRef<'_>) -> *mut T {
                let ptr_to_list_entry = self.entry.get();
                // SAFETY: valid pointer, from UnsafeCell get()
                let ptr_to_next_ptr = unsafe { &mut (*ptr_to_list_entry).next as *mut *mut T };
                // SAFETY: ptr_to_next_ptr is a valid pointer to an RCU pointer field of self
                unsafe { rcu_dereference(ptr_to_next_ptr, ctx) }
            }
        }

        /// Allows retrieving an `RCULinks` field
        pub trait RCUGetLinks {
            /// The type the `RCULinks` is embedded in
            type EntryType: RCUGetLinks + GetRCUHead;

            /// Retrieve an `RCULinks` field from `self`
            fn get_links(data: &Self::EntryType) -> &RCULinks<Self::EntryType>;
        }

        /// A linked list with RCU-protected elements
        ///
        /// # Invariants
        ///
        /// `head` is either null or a valid RCU pointer, and all list
        /// elements are owned by the list
        pub struct RCUList<T: RCUGetLinks + GetRCUHead> {
            head: *mut T::EntryType,
        }

        impl<T: RCUGetLinks + GetRCUHead> RCUList<T> {
            /// Initialize a null `RCUList`
            pub const fn new() -> RCUList<T> {
                RCUList {
                    head: core::ptr::null_mut(),
                }
            }

            /// Returns a cursor for immutably traversing the list
            #[inline]
            pub fn cursor_front_rcu<'a, 'b>(
                &'a self,
                ctx: RCUReadLockRef<'b>,
            ) -> RCUListCursor<'a, 'b, T> {
                RCUListCursor {
                    // SAFETY: self.head is an RCU pointer, & ref to self is held
                    cur: NonNull::new(unsafe {
                        rcu_dereference(
                            &self.head as *const *mut T::EntryType as *mut *mut T::EntryType,
                            ctx,
                        )
                    }),
                    rcu_ctx: ctx,
                    _list: PhantomData,
                }
            }

            /// Returns a cursor allowing the list to be safely mutated
            /// via RCU to atomically replace or remove items
            #[inline]
            pub fn cursor_front_mut_rcu<'a, 'b>(
                &'a mut self,
                ctx: RCUReadLockRef<'b>,
            ) -> RCUListCursorMut<'a, 'b, T> {
                RCUListCursorMut {
                    // SAFETY: self.head is an RCU pointer, &mut ref to self is held
                    cur: NonNull::new(unsafe {
                        rcu_dereference(&mut self.head as *mut *mut T::EntryType, ctx)
                    }),
                    list: self,
                    rcu_ctx: ctx,
                }
            }

            /// Retuns a cursor providing raw mutable access to the list's elements
            #[inline]
            pub fn cursor_front_inplace_mut_rcu<'a, 'b>(
                &'a self,
                ctx: RCUReadLockRef<'b>,
            ) -> RCUListCursorInplaceMut<'a, 'b, T> {
                RCUListCursorInplaceMut {
                    // SAFETY: self.head is an RCU pointer, & ref to self is held
                    cur: NonNull::new(unsafe {
                        rcu_dereference(
                            &self.head as *const *mut T::EntryType as *mut *mut T::EntryType,
                            ctx,
                        )
                    }),
                    rcu_ctx: ctx,
                    _list: PhantomData,
                }
            }

            /// Adds a new item to the front of the list
            pub fn push_front_rcu(&mut self, new: Box<T::EntryType>, ctx: RCUReadLockRef<'_>) {
                // convert box to raw pointer to prevent drop
                let new_ptr = Box::into_raw(new);
                // SAFETY: new list item and its fields are owned
                let new_list_entry = unsafe { &mut *T::get_links(&*new_ptr).entry.get() };
                // save pointer to previous head
                let old_head = self.head;
                // set up new element's links
                new_list_entry.prev = core::ptr::null_mut();
                new_list_entry.next = old_head;
                // SAFETY: self.head is an RCU pointer, &mut ref to self is held
                unsafe {
                    rcu_assign_pointer(&mut self.head as *mut *mut T::EntryType, new_ptr, ctx);
                }
                // if list was not empty, set up old head to refer back to the new item
                if old_head != core::ptr::null_mut() {
                    // SAFETY: read access of known valid pointer to owned item.
                    // Read-only RCU operations will not write to this value
                    let old_head_list_entry_ptr = unsafe { T::get_links(&*old_head).entry.get() };
                    // SAFETY: pointer is valid as it comes from get() on an UnsafeCell,
                    // and read-only RCU operations will not access prev ptrs
                    unsafe {
                        (*old_head_list_entry_ptr).prev = new_ptr;
                    }
                }
            }
        }

        impl<T: GetRCUHead + RCUGetLinks> Drop for RCUList<T> {
            fn drop(&mut self) {
                // remove and free all elements
                with_rcu_read_lock(|ctx| {
                    let mut c = self.cursor_front_mut_rcu(ctx);
                    while let Some(_) = c.current() {
                        c.remove_current_rcu();
                    }
                });
            }
        }

        /// Cursor allowing immutable RCU access to list and its elements
        ///
        /// # Invariants
        ///
        /// `cur` (optionally) points to an element owned by the relevant list
        pub struct RCUListCursor<'a, 'b, T: RCUGetLinks + GetRCUHead> {
            cur: Option<NonNull<T::EntryType>>,
            _list: PhantomData<&'a RCUList<T::EntryType>>,
            rcu_ctx: RCUReadLockRef<'b>,
        }

        impl<'a, 'b, T: RCUGetLinks + GetRCUHead> RCUListCursor<'a, 'b, T> {
            /// Returns a reference to the current item
            #[inline]
            pub fn current(&self) -> Option<&T::EntryType> {
                // SAFETY: self.cur points to list-owned item and & ref to list is held
                Some(unsafe { &*self.cur?.as_ptr() })
            }

            /// Safely moves the cursor to the next item
            #[inline]
            pub fn move_next_rcu(&mut self) {
                if let Some(p) = self.cur {
                    // SAFETY: self.cur points to list-owned item and & ref to list is held
                    let next_ptr =
                        unsafe { T::get_links(&*p.as_ptr()).rcu_dereference_next(self.rcu_ctx) };
                    self.cur = NonNull::new(next_ptr);
                }
            }
        }

        /// Cursor allowing raw mutable access to the list's elements
        ///
        /// # Invariants
        ///
        /// `cur` (optionally) points to an element owned by the relevant list
        pub struct RCUListCursorInplaceMut<'a, 'b, T: RCUGetLinks + GetRCUHead> {
            cur: Option<NonNull<T::EntryType>>,
            _list: PhantomData<&'a RCUList<T::EntryType>>,
            rcu_ctx: RCUReadLockRef<'b>,
        }

        impl<'a, 'b, T: RCUGetLinks + GetRCUHead> RCUListCursorInplaceMut<'a, 'b, T> {
            /// Returns a raw pointer to the current item
            #[inline]
            pub fn current_mut(&mut self) -> Option<*mut T::EntryType> {
                Some(self.cur?.as_ptr())
            }

            /// Safely moves the cursor to the next item
            #[inline]
            pub fn move_next_rcu(&mut self) {
                if let Some(p) = self.cur {
                    // SAFETY: self.cur points to list-owned item and & ref to list is held
                    let next_ptr = unsafe {
                        T::get_links(&mut *p.as_ptr()).rcu_dereference_next(self.rcu_ctx)
                    };
                    self.cur = NonNull::new(next_ptr);
                }
            }
        }

        /// Cursor allowing mutable RCU access to list allowing elements
        /// to be replaced and removed
        ///
        /// # Invariants
        ///
        /// `cur` (optionally) points to an element owned by the relevant list
        pub struct RCUListCursorMut<'a, 'b, T: RCUGetLinks + GetRCUHead> {
            cur: Option<NonNull<T::EntryType>>,
            list: &'a mut RCUList<T>,
            rcu_ctx: RCUReadLockRef<'b>,
        }

        impl<'a, 'b, T: RCUGetLinks + GetRCUHead> RCUListCursorMut<'a, 'b, T> {
            /// Returns a reference to the current item
            #[inline]
            pub fn current(&self) -> Option<&T::EntryType> {
                // SAFETY: self.cur points to list-owned item and & ref to list is held
                Some(unsafe { &*self.cur?.as_ptr() })
            }

            /// Safely moves the cursor to the next item
            #[inline]
            pub fn move_next_rcu(&mut self) {
                if let Some(p) = self.cur {
                    // SAFETY: self.cur points to list-owned item and & ref to list is held
                    let next_ptr =
                        unsafe { T::get_links(&*p.as_ptr()).rcu_dereference_next(self.rcu_ctx) };
                    self.cur = NonNull::new(next_ptr);
                }
            }

            /// Atomically removes the current item
            pub fn remove_current_rcu(&mut self) {
                if let Some(p) = self.cur {
                    // SAFETY: self.cur points to list-owned item and & ref to list is held
                    let cur_list_entry = unsafe { &*T::get_links(&*p.as_ptr()).entry.get() };
                    // get pointer to prev item
                    let prev_ptr = cur_list_entry.prev;
                    // get pointer to next item
                    let next_ptr = cur_list_entry.next;
                    // if next ptr is not null

                    if next_ptr != core::ptr::null_mut() {
                        // SAFETY: next ptr is not null, points to owned item
                        let next_list_entry_ptr = unsafe { T::get_links(&*next_ptr).entry.get() };
                        // SAFETY: accessing owned item
                        unsafe {
                            (*next_list_entry_ptr).prev = prev_ptr;
                        }
                    }
                    // calculate which 'next' pointer to assign to
                    let next_ptr_ptr = if prev_ptr == core::ptr::null_mut() {
                        &mut self.list.head as *mut *mut T::EntryType
                    } else {
                        // SAFETY: prev pointer is not null, points to owned item
                        let prev_list_entry_ptr = unsafe { T::get_links(&*prev_ptr).entry.get() };
                        // SAFETY: dereferencing known valid ptr from UnsafeCell get()
                        unsafe { &mut (*prev_list_entry_ptr).next as *mut *mut T::EntryType }
                    };
                    // SAFETY: mutable reference to list is held so write access
                    // is unique, and concurrent read-only RCU accesses are safe
                    unsafe {
                        rcu_assign_pointer(next_ptr_ptr, next_ptr, self.rcu_ctx);
                    }
                    // update self.cur
                    self.cur = NonNull::new(next_ptr);
                    // SAFETY: pointer to dynamically allocated item, no other refs exist
                    unsafe { rcu_free(p.as_ptr(), self.rcu_ctx) };
                }
            }

            /// Atomically replaces the current item
            pub fn replace_current_rcu(&mut self, new: Box<T::EntryType>) {
                if let Some(p) = self.cur {
                    // convert box to raw pointer to prevent drop
                    let new_ptr = Box::into_raw(new);
                    // SAFETY: new item is owned
                    let new_list_entry_ptr = unsafe { T::get_links(&*new_ptr).entry.get() };
                    // SAFETY: p is valid pointer to owned item
                    let cur_list_entry_ref = unsafe { &*T::get_links(&*p.as_ptr()).entry.get() };
                    let prev_ptr = cur_list_entry_ref.prev;
                    let next_ptr = cur_list_entry_ref.next;
                    // SAFETY: new list item is owned
                    unsafe {
                        (*new_list_entry_ptr).prev = prev_ptr;
                        (*new_list_entry_ptr).next = next_ptr;
                    }
                    // calculate which 'next' pointer to assign to
                    let next_ptr_ptr = if prev_ptr == core::ptr::null_mut() {
                        &mut self.list.head as *mut *mut T::EntryType
                    } else {
                        // prev pointer is not null so must be valid node
                        let prev_list_entry_ptr = unsafe { T::get_links(&*prev_ptr).entry.get() };
                        // SAFETY: accessing field of valid owned item
                        unsafe { &mut (*prev_list_entry_ptr).next as *mut *mut T::EntryType }
                    };
                    // SAFETY: mutable reference to list is held so write access
                    // is unique, and concurrent read-only RCU accesses are safe
                    unsafe {
                        rcu_assign_pointer(next_ptr_ptr, new_ptr, self.rcu_ctx);
                    }
                    // set up prev ptr of next element if necessary
                    if next_ptr != core::ptr::null_mut() {
                        // SAFETY: next is non-null and owned
                        let next_list_entry_ptr = unsafe { T::get_links(&*next_ptr).entry.get() };
                        // SAFETY: accessing field of owned item
                        unsafe {
                            (*next_list_entry_ptr).prev = new_ptr;
                        }
                    }
                    // update cursor to point to new item
                    self.cur = NonNull::new(new_ptr);
                    // SAFETY: pointer to dynamically allocated item, no other refs exist
                    unsafe { rcu_free(p.as_ptr(), self.rcu_ctx) };
                }
            }
        }
    }
}

/// Process and thread manangement functionality
pub mod task {

    use crate::bindings::*;
    use crate::prelude::{Box, CStr};
    use crate::yama_rust_interfaces::context::*;
    use crate::yama_rust_interfaces::rcu::rcu_dereference;
    use crate::yama_rust_interfaces::rcu::rcu_dereference_const;
    use crate::yama_rust_interfaces::rcu::RCUReadLockRef;
    use core::convert::TryInto;
    use core::marker::PhantomData;
    use core::ptr::NonNull;

    /// RAII struct representing a `task_struct` with its reference count
    /// incremented.
    pub struct TaskStruct {
        ptr: NonNull<task_struct>,
    }

    impl TaskStruct {
        /// Creates a new `TaskStruct` from a raw pointer, incrementing
        /// its reference counter
        #[inline]
        pub(crate) fn from_ptr(ptr: *mut task_struct) -> Option<TaskStruct> {
            let p = NonNull::new(ptr)?;
            // SAFETY: ptr is not null
            unsafe {
                get_task_struct_exported(ptr);
            }
            Some(TaskStruct { ptr: p })
        }

        /// Creates a new `TaskStruct` from a `NonNull` pointer, incrementing
        /// its reference counter
        #[inline]
        pub(crate) fn from_nonnull(ptr: NonNull<task_struct>) -> TaskStruct {
            // SAFETY: ptr is not null
            unsafe {
                get_task_struct_exported(ptr.as_ptr());
            }
            TaskStruct { ptr }
        }

        /// Creates a new `TaskStruct` based on a PID, incrementing
        /// its reference counter
        #[inline]
        pub fn from_pid(pid: pid_t) -> Option<TaskStruct> {
            // SAFETY: FFI call
            let ptr = unsafe { find_get_task_by_vpid(pid) };
            TaskStruct::from_ptr(ptr)
        }

        /// Creates a new `TaskStruct` for the current task
        #[inline]
        pub fn current() -> Option<TaskStruct> {
            // SAFETY: FFI call
            let ptr = unsafe { get_current_exported() };
            TaskStruct::from_ptr(ptr)
        }

        /// Returns a `TaskStructRef` referring to the given `TaskStruct`.
        /// The borrow checker will ensure this instance does not outlive its
        /// corresponding `TaskStruct`, ensuring the reference count remains held
        #[inline]
        pub const fn get_ref<'a>(&'a self) -> TaskStructRef<'a> {
            TaskStructRef {
                ptr: self.ptr,
                _marker: PhantomData,
            }
        }

        /// Returns a `TaskStructID` for the given `TaskStruct`
        #[inline]
        pub const fn get_id(&self) -> TaskStructID {
            TaskStructID { ptr: self.ptr }
        }
    }

    impl Drop for TaskStruct {
        #[inline]
        fn drop(&mut self) {
            // SAFETY: ptr is not null
            unsafe {
                // decrement the reference counter
                put_task_struct_exported(self.ptr.as_ptr());
            }
        }
    }

    /// Represents a `task_struct` pointer that is never dereferenced,
    /// only being used for ID and comparison
    #[derive(Copy, Clone)]
    pub struct TaskStructID {
        ptr: NonNull<task_struct>,
    }

    impl TaskStructID {
        /// Converts a `TaskStructID` to a `TaskStructRef`
        ///
        /// # Safety
        ///
        /// The caller must ensure the returned `TaskStructRef`
        /// does not outlive its `task_struct`
        #[inline]
        pub const unsafe fn get_tmp_ref(&self) -> TaskStructRef<'_> {
            TaskStructRef {
                ptr: self.ptr,
                _marker: PhantomData,
            }
        }

        /// Returns the inner `task_struct` pointer
        #[inline]
        pub const fn get_ptr(&self) -> *mut task_struct {
            self.ptr.as_ptr()
        }
    }

    impl<'a> PartialEq for TaskStructID {
        #[inline]
        fn eq(&self, other: &Self) -> bool {
            self.ptr == other.ptr
        }
    }

    /// Ties a `task_struct` pointer to a `TaskStruct`, allowing this
    /// type to be freely copied and passed as arguments, with the
    /// borrow checker ensuring it does not outlive its `TaskStruct`
    #[derive(Copy, Clone)]
    pub struct TaskStructRef<'a> {
        ptr: NonNull<task_struct>,
        _marker: PhantomData<&'a TaskStruct>,
    }

    impl<'a> PartialEq for TaskStructRef<'a> {
        #[inline]
        fn eq(&self, other: &Self) -> bool {
            self.ptr == other.ptr
        }
    }

    impl<'a> TaskStructRef<'a> {
        /// Creates a `TaskStructRef` directly from a raw pointer
        ///
        /// # Safety
        ///
        /// The returned `TaskStructRef` must not outlive the
        /// relevant `task_struct`
        #[inline]
        pub(crate) unsafe fn from_ptr(
            ptr: *mut task_struct,
            _ctx: EventContextRef<'a>,
        ) -> Option<TaskStructRef<'a>> {
            let p = NonNull::new(ptr)?;
            Some(TaskStructRef {
                ptr: p,
                _marker: PhantomData,
            })
        }

        /// Returns a `TaskStructRef` for the current task
        #[inline]
        pub fn current(_ctx: EventContextRef<'a>) -> TaskStructRef<'a> {
            // SAFETY: current should never be null in EventContext
            let p = unsafe { NonNull::new_unchecked(get_current_exported()) };
            TaskStructRef {
                ptr: p,
                _marker: PhantomData,
            }
        }

        /// Returns a new `TaskStruct` from a `TaskStructRef`,
        /// incrementing the reference counter
        #[inline]
        pub fn get_task_struct(self) -> TaskStruct {
            TaskStruct::from_nonnull(self.ptr)
        }

        /// Returns a corresponding `TaskStructID`
        #[inline]
        pub const fn get_id(self) -> TaskStructID {
            TaskStructID { ptr: self.ptr }
        }

        /// Return's the task's PID
        #[inline]
        pub const fn pid(self) -> pid_t {
            // SAFETY: reading field of non-null task_struct
            unsafe { (*self.ptr.as_ptr()).pid }
        }

        /// Checks if the tasks are in the same thread group
        #[inline]
        pub fn same_thread_group(self, other: TaskStructRef<'_>) -> bool {
            // SAFETY: reading field of non-null task_struct
            unsafe { (*self.ptr.as_ptr()).signal == (*other.ptr.as_ptr()).signal }
        }

        /// Checks if the task is a thread group leader
        #[inline]
        pub fn thread_group_leader(self) -> bool {
            // SAFETY: reading field of non-null task_struct
            unsafe { (*self.ptr.as_ptr()).exit_signal >= 0 }
        }

        /// Checks if the task is alive
        #[inline]
        pub fn pid_alive(self) -> bool {
            // SAFETY: reading field of non-null task_struct
            unsafe { (*self.ptr.as_ptr()).thread_pid != core::ptr::null_mut() }
        }

        /// Checks if the given flags are set
        #[inline]
        pub fn flags_set(self, flags: u32) -> bool {
            // SAFETY: reading field of non-null task_struct
            unsafe { (*self.ptr.as_ptr()).flags & flags != 0 }
        }

        /// Checks if the current task has the given capability in the task's namespace
        #[inline]
        pub fn current_ns_capable(self, cap: u32, ctx: RCUReadLockRef<'_>) -> bool {
            // SAFETY: self.ptr is non null
            let task_cred = unsafe {
                rcu_dereference_const(&(*self.ptr.as_ptr()).real_cred as *const *const cred, ctx)
            };
            // SAFETY: real_cred should be valid
            let user_ns = unsafe { (*task_cred).user_ns };
            // SAFETY: FFI call
            unsafe { ns_capable_exported(user_ns, cap.try_into().unwrap()) >= 0 }
        }

        /// Checks if the task has the given capability in the current task's namespace
        #[inline]
        pub fn has_ns_capability_current(self, cap: u32) -> bool {
            // SAFETY: self.ptr is non null
            unsafe {
                has_ns_capability(
                    self.ptr.as_ptr(),
                    current_user_ns_exported(),
                    cap.try_into().unwrap(),
                )
            }
        }

        /// Returns the task's command line string
        pub fn get_cmdline_str(self) -> Option<Box<CStr>> {
            // SAFETY: self.ptr is non null
            let cmdline_str_ptr =
                unsafe { kstrdup_quotable_cmdline(self.ptr.as_ptr(), GFP_KERNEL) };
            if cmdline_str_ptr != core::ptr::null_mut() {
                // SAFETY: cmdline_str_ptr is not null and was provided by the kernel
                let cmdline_str = unsafe {
                    // create a reference to a CStr from the raw char pointer
                    CStr::from_char_ptr(cmdline_str_ptr)
                };
                // SAFETY: cmdline_str points to dynamically allocated string
                unsafe {
                    // convert the &CStr to a raw pointer and then a Box
                    // enabling the dynamically allocated string to be
                    // automatically freed
                    Some(Box::from_raw(cmdline_str as *const _ as *mut _))
                }
            } else {
                None
            }
        }

        /// Returns the task's real parent task
        #[inline]
        pub fn get_real_parent(self, ctx: RCUReadLockRef<'a>) -> TaskStructRef<'a> {
            // SAFETY: self.ptr is not null, real_parent is an RCU pointer
            let ptr = unsafe {
                rcu_dereference(&mut (*self.ptr.as_ptr()).real_parent as *mut *mut _, ctx)
            };
            if ptr == core::ptr::null_mut() {
                self
            } else {
                // SAFETY: ptr is not null
                let ptr = unsafe { NonNull::new_unchecked(ptr) };
                TaskStructRef {
                    ptr,
                    _marker: PhantomData,
                }
            }
        }

        /// Returns the task's thread group leader
        #[inline]
        pub fn get_thread_group_leader(self, ctx: RCUReadLockRef<'a>) -> TaskStructRef<'a> {
            if self.thread_group_leader() {
                self
            } else {
                // SAFETY: self.ptr is not null, group_leader is RCU pointer
                let ptr = unsafe {
                    rcu_dereference(&mut (*self.ptr.as_ptr()).group_leader as *mut *mut _, ctx)
                };
                // SAFETY: group leader should not be null if not thread group leader
                let ptr = unsafe { NonNull::new_unchecked(ptr) };
                TaskStructRef {
                    ptr,
                    _marker: PhantomData,
                }
            }
        }

        /// Returns the task's ptrace parent
        #[inline]
        pub fn get_ptrace_parent(self, ctx: RCUReadLockRef<'a>) -> Option<TaskStructRef<'a>> {
            // SAFETY: self.ptr is not null, parent is RCU pointer
            let ptr =
                unsafe { rcu_dereference(&mut (*self.ptr.as_ptr()).parent as *mut *mut _, ctx) };
            let ptr = NonNull::new(ptr)?;
            Some(TaskStructRef {
                ptr,
                _marker: PhantomData,
            })
        }

        /// Checks if the given task is the task's child
        #[inline]
        pub fn is_descendant(self, child: TaskStructRef<'_>, ctx: RCUReadLockRef<'_>) -> bool {
            let parent = self.get_thread_group_leader(ctx);
            let mut walker = child;
            while walker.pid() > 0 {
                walker = walker.get_thread_group_leader(ctx);
                if walker == parent {
                    return true;
                }
                walker = walker.get_real_parent(ctx);
            }
            return false;
        }
    }

    /// Checks if the current task has the given capability
    #[inline]
    pub fn current_capable(cap: i32) -> bool {
        // SAFETY: FFI call
        unsafe { capable_exported(cap) }
    }
}

/// Deferred execution through work queues
pub mod work_queue {

    use crate::bindings::*;
    use crate::container_of;
    use alloc::boxed::Box;
    use core::cell::UnsafeCell;
    use core::marker::PhantomData;

    /// Represents a static work queue task function
    pub trait StaticWorkFunc {
        /// A static work function with no arguments or return values
        fn work_func();
    }

    /// C-compatible wrapper function for Rust static work function
    unsafe extern "C" fn static_work_func<T: StaticWorkFunc>(_work: *mut work_struct) {
        T::work_func();
    }

    /// A static work queue task
    pub struct StaticWorkStruct<T: StaticWorkFunc> {
        work: UnsafeCell<work_struct>,
        _marker: PhantomData<T>,
    }

    impl<T: StaticWorkFunc> StaticWorkStruct<T> {
        /// Initializes a new static work queue task
        ///
        /// # Arguments
        ///
        /// * `this`: a reference to the global variable being initialized. If the
        /// wrong reference is passed, the task will fail to be scheduled
        pub const fn new(this: &'static StaticWorkStruct<T>) -> StaticWorkStruct<T> {
            // SAFETY: pointer from UnsafeCell get() is valid
            let this_entry_ptr = unsafe { &((*this.work.get()).entry) as *const _ as *mut _ };
            StaticWorkStruct {
                work: UnsafeCell::new(work_struct {
                    data: atomic_long_t {
                        counter: (WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC),
                    },
                    entry: list_head {
                        next: this_entry_ptr,
                        prev: this_entry_ptr,
                    },
                    func: Some(static_work_func::<T>),
                }),
                _marker: PhantomData,
            }
        }

        /// Schedule the task
        #[inline]
        pub fn schedule(&'static self) {
            // SAFETY: self.work.get() pointer is valid for 'static
            unsafe {
                schedule_work_exported(self.work.get() as *const _ as *mut _);
            }
        }
    }

    /// Initialize a global static work struct, automtically passing
    /// the correct reference to the `init` function
    #[macro_export]
    macro_rules! init_static_work_struct {
        ($(#[$outer:meta])* $v:vis static $id:ident : StaticWorkStruct < $t:ty > ;) => {
            $(#[$outer])*
            $v static $id: StaticWorkStruct<$t> = StaticWorkStruct::new(&$id);
        };
    }

    // SAFETY: this type's methods do not read or write any of its data
    unsafe impl<T: StaticWorkFunc> Sync for StaticWorkStruct<T> {}

    /// A dynamically allocated work queue task function
    pub trait DynamicWorkFunc {
        /// The data type for the task's assocated data
        type AssociatedDataType;

        /// A work queue task function for a dynamically allocated work queue task
        fn work_func(data: &Self::AssociatedDataType);
    }

    /// C-compatible wrapper function for a dynamic work queue task function
    unsafe extern "C" fn dynamic_work_func<T: DynamicWorkFunc>(work: *mut callback_head) {
        // locate the DynamicWorkStruct of which `work` is a field
        // SAFETY: callback_head points to field of Box-allocated work payload
        let payload = unsafe {
            Box::from_raw(
                container_of!(work, DynamicWorkStruct<T>, work_head) as *mut DynamicWorkStruct<T>
            )
        };
        T::work_func(&(*payload).data);
        // box goes out of scope and dynamicaly allocated payload is freed
    }

    /// A dynamic work queue task
    pub struct DynamicWorkStruct<T: DynamicWorkFunc> {
        data: T::AssociatedDataType,
        work_head: callback_head,
    }

    impl<T: DynamicWorkFunc> DynamicWorkStruct<T> {
        /// Creates and schedules a dynamic work queue task
        ///
        /// # Arguments:
        ///
        /// * `data`: the data to be stored with the task and
        /// passed to its work function
        pub fn create_and_schedule(data: T::AssociatedDataType) {
            // dynamically allocate a new payload
            let payload: Box<DynamicWorkStruct<T>> = Box::try_new(DynamicWorkStruct {
                // the task's data
                data: data,
                work_head: callback_head {
                    next: core::ptr::null_mut(),
                    // the task's work function
                    func: Some(dynamic_work_func::<T>),
                },
            })
            .unwrap();
            // covert to raw pointer to prevent drop
            let payload = Box::into_raw(payload);
            // SAFETY: FFI call
            let current = unsafe { get_current_exported() };
            // schedule the task
            // SAFETY: payload is valid pointer from Box
            unsafe {
                task_work_add(
                    current,
                    &(*payload).work_head as *const _ as *mut _,
                    task_work_notify_mode_TWA_RESUME,
                )
            };
        }
    }
}

/// User-space communication and configuration via sysctl
pub mod sysctl {

    use crate::bindings::*;
    use crate::c_types::*;
    use crate::prelude::*;
    use crate::str::CStr;
    use core::cell::UnsafeCell;
    use core::marker::PhantomData;

    /// Newtype wrapper around `ctl_path`
    #[repr(transparent)]
    pub struct SysctlPath(ctl_path);

    impl SysctlPath {
        /// Initializes a new path segment specifier from a string
        #[inline]
        pub const fn new(path: &'static CStr) -> SysctlPath {
            SysctlPath(ctl_path {
                procname: path.as_char_ptr(),
            })
        }

        /// Initializes a null path segment specifier
        #[inline]
        pub const fn null() -> SysctlPath {
            SysctlPath(ctl_path {
                procname: core::ptr::null(),
            })
        }
    }

    /// Maps a list of strings to an array of `SysctlPath` instances
    #[macro_export]
    macro_rules! gen_sysctl_path {
        ( $($p:literal),+ ) => {
            &[
                $(
                    SysctlPath::new(c_str!($p)),
                )*
                SysctlPath::null(),
            ]
        }
    }

    /// Newtype wrapper around a ctl_table
    ///
    /// # Invariants
    ///
    /// `data`, `extra1` and `extra2` pointees are valid and safe to read
    #[repr(transparent)]
    pub struct SysctlTable(ctl_table);

    impl SysctlTable {
        /// Returns the data value
        #[inline]
        pub const fn get_data(&self) -> i32 {
            // SAFETY: data field is safe to read
            unsafe { *(self.0.data as *const i32) }
        }

        /// Returns the minimum data value
        #[inline]
        pub const fn get_min(&self) -> i32 {
            // SAFETY: extra1 field is safe to read
            unsafe { *(self.0.extra1 as *const i32) }
        }

        /// Returns the maximum data value
        #[inline]
        pub const fn get_max(&self) -> i32 {
            // SAFETY: extra2 field is safe to read
            unsafe { *(self.0.extra1 as *const i32) }
        }

        /// Locks the data value to the maximum
        #[inline]
        pub fn lock_max(&mut self) {
            self.0.extra1 = self.0.extra2
        }

        /// Locks the data value to the minimum
        #[inline]
        pub fn lock_min(&mut self) {
            self.0.extra2 = self.0.extra1
        }
    }

    /// Represents a hook function used to control sysctl writes from userspace
    pub trait SysctlIntWriteHook {
        /// Mediates sysctl write accesses
        ///
        /// # Arguments
        ///
        /// * `write_hook`: the sysctl table representing the value being accessed
        fn write_hook(table: &mut SysctlTable) -> Result;
    }

    /// C-compatible wrapper function for handling sysctl accesses
    unsafe extern "C" fn dointvec_minmax<T: SysctlIntWriteHook>(
        table: *mut ctl_table,
        write: c_int,
        buffer: *mut c_void,
        lenp: *mut c_size_t,
        ppos: *mut loff_t,
    ) -> c_int {
        // SAFETY: table is provided by the kernel
        let mut table_copy = unsafe { SysctlTable(*table) };
        // call write hook if write is being attempted
        if write != 0 {
            if let Err(e) = T::write_hook(&mut table_copy) {
                return e.to_kernel_errno();
            }
        }
        // SAFETY: table_copy is valid, args passed through from kernel
        unsafe {
            // perform read or write access
            proc_dointvec_minmax(
                &mut table_copy as *mut _ as *mut _,
                write,
                buffer,
                lenp,
                ppos,
            )
        }
    }

    /// A bounded integer value to be exposed via sysctl
    pub struct BoundedInt {
        val: UnsafeCell<c_int>,
        min: c_int,
        max: c_int,
    }

    impl BoundedInt {
        /// Initializes a new instance
        #[inline]
        pub const fn new(val: i32, min: i32, max: i32) -> BoundedInt {
            BoundedInt {
                val: UnsafeCell::new(val),
                min,
                max,
            }
        }

        /// Returns the current value
        #[inline]
        pub const fn get_val(&self) -> i32 {
            // SAFETY: field of self is being read
            unsafe { *self.val.get() }
        }
    }

    // SAFETY: public interface only allows reading data
    unsafe impl Sync for BoundedInt {}

    /// An integer value exposed via sysctl
    pub struct SysctlInt<T: SysctlIntWriteHook> {
        // the data value itself
        _data: &'static BoundedInt,
        // the sysctl path defining the location of the procfs file
        sysctl_path: &'static [SysctlPath],
        // the sysctl table defining the procfs file
        sysctl_table: UnsafeCell<[ctl_table; 2]>,
        _marker: PhantomData<T>,
    }

    impl<T: SysctlIntWriteHook> SysctlInt<T> {
        /// Initialize a new sysctl integer
        pub const fn new(
            data: &'static BoundedInt,
            name: &'static CStr,
            mode: u16,
            path: &'static [SysctlPath],
        ) -> SysctlInt<T> {
            SysctlInt {
                _data: data,
                sysctl_path: path,
                sysctl_table: UnsafeCell::new([
                    ctl_table {
                        procname: name.as_char_ptr(),
                        data: &data.val as *const _ as *mut c_void,
                        maxlen: core::mem::size_of::<c_int>() as _,
                        mode: mode as _,
                        child: core::ptr::null_mut(),
                        proc_handler: Some(dointvec_minmax::<T>),
                        poll: core::ptr::null_mut(),
                        extra1: &data.min as *const _ as *mut c_void,
                        extra2: &data.max as *const _ as *mut c_void,
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
                ]),
                _marker: PhantomData,
            }
        }

        /// register the sysctl integer
        pub fn register(&'static self) {
            // SAFETY: pointers to values which are owned,
            // or to which refs are held, for 'static
            unsafe {
                register_sysctl_paths(
                    self.sysctl_path.as_ptr() as *const _,
                    self.sysctl_table.get() as *mut _,
                )
            };
        }
    }

    // SAFETY: stored pointers are never dereferenced/leaked in type's interface
    unsafe impl<T: SysctlIntWriteHook> Sync for SysctlInt<T> {}
}

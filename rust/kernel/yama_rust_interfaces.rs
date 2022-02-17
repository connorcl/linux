use crate::prelude::*;
use crate::bindings::*;
use crate::c_types::*;
use crate::error::Error;
use crate::str::CStr;
use core::marker::PhantomData;
use alloc::boxed::Box;


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

    fn ptrace_access_check(child: *mut task_struct, mode: c_uint) -> Result {
        return Ok(());
    }

    fn ptrace_traceme(parent: *mut task_struct) -> Result {
        return Ok(());
    }

    fn task_free(task: *mut task_struct) {
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
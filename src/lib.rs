use std::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::atomic::AtomicBool,
};

use hooker::gen_hook_info;
use thiserror::Error;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{FreeLibrary, HMODULE},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{
                VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE,
                PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
            },
            ProcessStatus::{GetModuleInformation, MODULEINFO},
            Threading::GetCurrentProcess,
        },
    },
};

/// a lock which just fails when trying to lock it while it is already locked.
struct SingleLock<T> {
    value: UnsafeCell<T>,
    is_locked: AtomicBool,
}
impl<T> SingleLock<T> {
    /// creates a new lock with the given value
    const fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
            is_locked: AtomicBool::new(false),
        }
    }
    /// locks the lock and returns a guard. if the lock is already locked, returns `None`.
    fn lock(&self) -> Option<SingleLockGuard<T>> {
        if self
            .is_locked
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return None;
        }
        Some(SingleLockGuard { lock: self })
    }
}
unsafe impl<T> Send for SingleLock<T> {}
unsafe impl<T> Sync for SingleLock<T> {}

/// a single lock guard which unlocks the lock when dropped.
struct SingleLockGuard<'a, T> {
    lock: &'a SingleLock<T>,
}
impl<'a, T> Drop for SingleLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock
            .is_locked
            .store(false, std::sync::atomic::Ordering::Release)
    }
}
impl<'a, T> Deref for SingleLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}
impl<'a, T> DerefMut for SingleLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.value.get() }
    }
}

/// a static hook which can be used to store hook information as a static variable so that it can easily be accessed from anywhere.
pub struct StaticHook {
    hook: SingleLock<Option<Hook>>,
}
impl StaticHook {
    const HOOK_USED_MULTIPLE_TIMES_ERR_MSG: &'static str = "static hook used multiple times";

    /// creates a new, empty, static hook.
    pub const fn new() -> Self {
        Self {
            hook: SingleLock::new(None),
        }
    }
    /// locks the hook and returns a lock guard for it.
    ///
    /// # Panics
    ///
    /// panics if the lock is already held
    fn lock_hook(&self) -> SingleLockGuard<Option<Hook>> {
        self.hook
            .lock()
            .expect(Self::HOOK_USED_MULTIPLE_TIMES_ERR_MSG)
    }

    /// locks the hook, makes sure that it is empty, and returns a lock guard for it.
    ///
    /// # Panics
    ///
    /// panics if the lock is already held or if the hook is not empty
    fn lock_hook_and_assert_empty(&self) -> SingleLockGuard<Option<Hook>> {
        let hook = self.lock_hook();
        if hook.is_some() {
            panic!("{}", Self::HOOK_USED_MULTIPLE_TIMES_ERR_MSG)
        }
        hook
    }

    /// hooks the function with the given `fn_addr` from the given `module` such that when the function is called it instead jumps
    /// to the given `hook_to_addr`.
    ///
    /// # Panics
    ///
    /// panics if this static hook was already used to hook some function.
    pub fn hook_function(
        &self,
        module: HMODULE,
        fn_addr: usize,
        hook_to_addr: usize,
    ) -> Result<()> {
        let mut hook = self.lock_hook_and_assert_empty();
        let created_hook = hook_function(module, fn_addr, hook_to_addr)?;
        *hook = Some(created_hook);
        Ok(())
    }

    /// hooks the function with the `fn_name` from the library with the provided `library_name` such that when the function is called it instead jumps
    /// to the given `hook_to_addr`.
    ///
    /// # Panics
    ///
    /// panics if this static hook was already used to hook some function.
    pub fn hook_function_by_name(
        &self,
        library_name: PCSTR,
        fn_name: PCSTR,
        hook_to_addr: usize,
    ) -> Result<()> {
        let mut hook = self.lock_hook_and_assert_empty();
        let created_hook = hook_function_by_name(library_name, fn_name, hook_to_addr)?;
        *hook = Some(created_hook);
        Ok(())
    }

    /// returns a reference to the hook.
    ///
    /// # Panics
    ///
    /// panics if the static hook was not yet used to hook any function.
    pub fn get_hook(&self) -> &Hook {
        let hook_guard = self.lock_hook();
        let hook_opt = unsafe { &*(hook_guard.deref() as *const Option<Hook>) };
        hook_opt
            .as_ref()
            .expect("static hook used before hooking any function")
    }
}

/// a guard which calls `FreeLibrary` on the module handle when dropped.
struct ModuleHandleGuard(HMODULE);
impl Drop for ModuleHandleGuard {
    fn drop(&mut self) {
        let _ = unsafe { FreeLibrary(self.0) };
    }
}

/// hooks the function with the `fn_name` from the library with the provided `library_name` such that when the function is called it instead jumps
/// to the given `hook_to_addr`.
pub fn hook_function_by_name(
    library_name: PCSTR,
    fn_name: PCSTR,
    hook_to_addr: usize,
) -> Result<Hook> {
    let module_guard = ModuleHandleGuard(unsafe {
        LoadLibraryA(library_name).map_err(Error::FailedToLoadLibrary)?
    });
    let fn_addr =
        unsafe { GetProcAddress(module_guard.0, fn_name).ok_or(Error::NoFunctionWithThatName)? };
    hook_function(module_guard.0, fn_addr as usize, hook_to_addr)
}

/// hooks the function with the given `fn_addr` from the given `module` such that when the function is called it instead jumps
/// to the given `hook_to_addr`.
pub fn hook_function(module: HMODULE, fn_addr: usize, hook_to_addr: usize) -> Result<Hook> {
    let mut module_info_uninit: MaybeUninit<MODULEINFO> = MaybeUninit::uninit();
    unsafe {
        GetModuleInformation(
            GetCurrentProcess(),
            module,
            module_info_uninit.as_mut_ptr(),
            core::mem::size_of::<MODULEINFO>() as u32,
        )
        .map_err(Error::FailedToGetModuleInformation)?
    };
    let module_info = unsafe { module_info_uninit.assume_init() };
    let module_end_addr = module_info.lpBaseOfDll as usize + module_info.SizeOfImage as usize;
    let fn_max_possible_size = module_end_addr - fn_addr;
    let fn_possible_content =
        unsafe { core::slice::from_raw_parts(fn_addr as *const u8, fn_max_possible_size) };
    let hook_info = gen_hook_info(fn_possible_content, fn_addr as u64, hook_to_addr as u64)?;

    // allocate the trampoline and copy its code
    let mut trampiline_alloc = Allocation::new(hook_info.trampoline_size());
    let trampoline_code = hook_info.build_trampoline(trampiline_alloc.ptr as u64);
    let trampoline_alloc_slice = unsafe { trampiline_alloc.as_mut_slice() };
    trampoline_alloc_slice[..trampoline_code.len()].copy_from_slice(&trampoline_code);

    // done writing the trampoline, now make it executable
    trampiline_alloc.make_executable_and_read_only();

    // write the jumper
    let jumper_code = hook_info.jumper();
    let mut bytes_written = 0;
    unsafe {
        WriteProcessMemory(
            GetCurrentProcess(),
            fn_addr as *const _,
            jumper_code.as_ptr().cast(),
            jumper_code.len(),
            Some(&mut bytes_written),
        )
        .unwrap()
    }
    // make sure that all bytes were written
    assert_eq!(
        bytes_written,
        jumper_code.len(),
        "not all bytes of jumper were written to the start of the function"
    );

    Ok(Hook {
        trampoline: trampiline_alloc,
        fn_addr,
        hook_to_addr,
    })
}

/// a memory allocation
pub struct Allocation {
    ptr: *mut u8,
    size: usize,
}
impl Allocation {
    fn new(size: usize) -> Self {
        let ptr = unsafe { VirtualAlloc(None, size, MEM_COMMIT, PAGE_READWRITE) };
        if ptr.is_null() {
            // should never happen except for OOM, in which case the default behaviour is to panic anyways.
            panic!("failed to allocate read-write memory using VirtualAlloc");
        }
        Self {
            ptr: ptr.cast(),
            size,
        }
    }
    fn make_executable_and_read_only(&mut self) {
        let mut old_prot: MaybeUninit<PAGE_PROTECTION_FLAGS> = MaybeUninit::uninit();
        unsafe {
            VirtualProtect(
                self.ptr.cast(),
                self.size,
                PAGE_EXECUTE,
                old_prot.as_mut_ptr(),
            )
            .expect("failed to change memory protection to executable")
        }
    }
    /// # Safety
    /// must be called only if the memory still has write permissions
    unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) }
    }
    /// returns a pointer to the allocation
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }
    /// returns a mutable pointer to the allocation
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }
    /// returns the size of the allocation
    pub fn size(&self) -> usize {
        self.size
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.ptr.cast(), 0, MEM_RELEASE);
        }
    }
}
/// a hook that was placed on some function
pub struct Hook {
    trampoline: Allocation,
    fn_addr: usize,
    hook_to_addr: usize,
}
impl Hook {
    /// returns an address of a function which when called will simulate the original function behaviour without the hook.
    pub fn original_addr(&self) -> usize {
        self.trampoline.ptr as usize
    }
    /// provides an interface for calling a function which will simulate the original function behaviour without the hook.
    /// the generic argument `F` should be a function pointer signature of the original function (e.g `extern "C" fn(i32) -> i32`).
    ///
    /// # Safety
    ///
    /// the generic argument `F` must be a function pointer, and must have the correct signature of the original function.
    pub unsafe fn original<F: Copy>(&self) -> F {
        // make sure that the provided fn signature indeed looks like a function pointer
        assert!(
            core::mem::size_of::<F>() == core::mem::size_of::<usize>()
                && core::mem::align_of::<F>() == core::mem::align_of::<usize>(),
            "provided function signature type {} is not a function pointer",
            core::any::type_name::<F>()
        );
        let trampoline_ptr = self.trampoline.ptr;
        core::mem::transmute_copy(&trampoline_ptr)
    }
    /// returns the address of the hooked function
    pub fn fn_addr(&self) -> usize {
        self.fn_addr
    }
    /// returns the address that the function was hooked to
    pub fn hook_to_addr(&self) -> usize {
        self.hook_to_addr
    }
    /// returns a reference to the hook's trampoline
    pub fn trampoline(&self) -> &Allocation {
        &self.trampoline
    }
    /// returns the hook's trampoline
    pub fn into_trampoline(self) -> Allocation {
        self.trampoline
    }
}

/// an error that occurs while hooking a function
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to get module information")]
    FailedToGetModuleInformation(#[source] windows::core::Error),

    #[error("failed to load library")]
    FailedToLoadLibrary(#[source] windows::core::Error),

    #[error("no function with the provided name exists in the specified library")]
    NoFunctionWithThatName,

    #[error("failed to generate hook info")]
    FailedToGenHookInfo(
        #[source]
        #[from]
        hooker::HookError,
    ),
}

/// the result of hooking a function
pub type Result<T> = core::result::Result<T, Error>;

use core::num::NonZeroUsize;
use std::sync::LazyLock;

const NOP: u8 = 0x90;

#[cfg(target_os = "windows")]
static PAGE_SIZE: LazyLock<NonZeroUsize> = LazyLock::new(|| {
    let mut system_info = unsafe { std::mem::zeroed() };
    unsafe {
        use windows_sys::Win32::System::SystemInformation::GetSystemInfo;
        GetSystemInfo(&mut system_info)
    };
    NonZeroUsize::new(system_info.dwPageSize as usize).expect("failed to convert pagesz to usize")
});

#[cfg(target_family = "unix")]
static PAGE_SIZE: LazyLock<NonZeroUsize> = LazyLock::new(|| {
    let pagesz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let pagesz: usize = pagesz
        .try_into()
        .expect("failed to convert pagesz to usize");
    NonZeroUsize::new(pagesz).expect("failed to convert pagesz to usize")
});

/// A view into an executable memory map
pub struct ExecMapView {
    ptr: *mut u8,
    len: usize,
}

impl ExecMapView {
    /// Commit code to the memory map
    pub fn commit_code(&mut self, code: &[u8]) -> Result<(), std::io::Error> {
        if false
            && unsafe {
                libc::mprotect(
                    self.ptr.cast(),
                    code.len(),
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let mut_slice = unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) };
        mut_slice[..code.len()].copy_from_slice(code);
        if false
            && unsafe {
                libc::mprotect(
                    self.ptr.cast(),
                    code.len(),
                    libc::PROT_READ | libc::PROT_EXEC,
                )
            } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

unsafe impl Send for ExecMapView {}
unsafe impl Sync for ExecMapView {}

impl AsRef<[u8]> for ExecMapView {
    fn as_ref(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl core::ops::Deref for ExecMapView {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

/// An executable memory map consisting of an RWX region and a guard page
pub struct ExecMap {
    view: ExecMapView,
    #[cfg(target_family = "unix")]
    /// The total size of the memory map, including the guard page
    capacity: usize,
}

impl core::ops::Deref for ExecMap {
    type Target = ExecMapView;
    fn deref(&self) -> &Self::Target {
        &self.view
    }
}

impl core::ops::DerefMut for ExecMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.view
    }
}

impl ExecMap {
    #[cfg(target_family = "unix")]
    /// Create a new executable memory map
    pub fn new(size: NonZeroUsize) -> Result<Self, std::io::Error> {
        let size = size.get();
        let alloc_min_len = size.next_multiple_of(PAGE_SIZE.get());
        let ptr = unsafe {
            libc::mmap64(
                core::ptr::null_mut(),
                alloc_min_len + PAGE_SIZE.get(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        // initialize memory with something safe
        unsafe {
            core::slice::from_raw_parts_mut(ptr.cast(), alloc_min_len).fill(NOP);
        }

        unsafe {
            // set up guard page
            if libc::mprotect(
                ptr.byte_add(alloc_min_len).cast(),
                PAGE_SIZE.get(),
                libc::PROT_NONE,
            ) != 0
            {
                let mut err = std::io::Error::last_os_error();
                if libc::munmap(ptr, alloc_min_len + PAGE_SIZE.get()) != 0 {
                    err = std::io::Error::last_os_error();
                }
                return Err(err);
            }

            // set up executable page
            if libc::mprotect(
                ptr,
                alloc_min_len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            ) != 0
            {
                let mut err = std::io::Error::last_os_error();
                if libc::munmap(ptr, alloc_min_len + PAGE_SIZE.get()) != 0 {
                    err = std::io::Error::last_os_error();
                }
                return Err(err);
            }
        }

        Ok(Self {
            view: ExecMapView {
                ptr: ptr.cast(),
                len: size,
            },
            capacity: alloc_min_len + PAGE_SIZE.get(),
        })
    }

    #[cfg(target_os = "windows")]
    /// Create a new executable memory map
    pub fn new(size: NonZeroUsize) -> Result<Self, std::io::Error> {
        let size = size.get();

        let min_alloc_len = size.next_multiple_of(PAGE_SIZE.get());
        let ptr = unsafe {
            use windows_sys::Win32::System::Memory::VirtualAlloc;
            VirtualAlloc(
                core::ptr::null_mut(),
                min_alloc_len + PAGE_SIZE.get(),
                windows_sys::Win32::System::Memory::MEM_COMMIT
                    | windows_sys::Win32::System::Memory::MEM_RESERVE,
                windows_sys::Win32::System::Memory::PAGE_READWRITE,
            )
        };

        if ptr == core::ptr::null_mut() {
            return Err(std::io::Error::last_os_error());
        }

        // initialize memory with something safe
        unsafe {
            core::slice::from_raw_parts_mut(ptr.cast(), min_alloc_len).fill(NOP);
        }

        unsafe {
            use windows_sys::Win32::System::Memory::VirtualProtect;

            let mut old = 0;

            // set up guard page
            if VirtualProtect(
                ptr.byte_add(min_alloc_len).cast(),
                PAGE_SIZE.get(),
                windows_sys::Win32::System::Memory::PAGE_NOACCESS,
                &mut old,
            ) == 0
            {
                let mut err = std::io::Error::last_os_error();
                if windows_sys::Win32::System::Memory::VirtualFree(
                    ptr,
                    0,
                    windows_sys::Win32::System::Memory::MEM_RELEASE,
                ) != 0
                {
                    err = std::io::Error::last_os_error();
                }
                return Err(err);
            }

            // set up executable page
            if VirtualProtect(
                ptr,
                min_alloc_len,
                windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
                &mut old,
            ) == 0
            {
                let mut err = std::io::Error::last_os_error();
                if windows_sys::Win32::System::Memory::VirtualFree(
                    ptr,
                    0,
                    windows_sys::Win32::System::Memory::MEM_RELEASE,
                ) != 0
                {
                    err = std::io::Error::last_os_error();
                }
                return Err(err);
            }
        }

        Ok(Self {
            view: ExecMapView {
                ptr: ptr.cast(),
                len: size,
            },
        })
    }
}

#[cfg(target_family = "unix")]
impl Drop for ExecMap {
    fn drop(&mut self) {
        if unsafe { libc::munmap(self.ptr.cast(), self.capacity) } != 0 {
            panic!("failed to free memory: {}", std::io::Error::last_os_error());
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for ExecMap {
    fn drop(&mut self) {
        unsafe {
            if windows_sys::Win32::System::Memory::VirtualFree(
                self.ptr.cast(),
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            ) == 0
            {
                panic!("failed to free memory: {}", std::io::Error::last_os_error());
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_exec_map() {
        let _map = ExecMap::new(NonZeroUsize::new(16384).unwrap()).unwrap();
    }
}

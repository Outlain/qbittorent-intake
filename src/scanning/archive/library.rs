//! The entire unsafe libarchive boundary lives here. No pointer or borrowed
//! parser memory escapes; public metadata is copied into owned Rust values.
use super::*;
use std::{
    ffi::{c_char, c_int, c_uint, c_void, CStr},
    io::{Seek, SeekFrom},
};
type Archive = *mut c_void;
struct Api {
    _library: libloading::Library,
    new: unsafe extern "C" fn() -> Archive,
    free: unsafe extern "C" fn(Archive) -> c_int,
    filter: unsafe extern "C" fn(Archive) -> c_int,
    rar: unsafe extern "C" fn(Archive) -> c_int,
    rar5: unsafe extern "C" fn(Archive) -> c_int,
    zip: unsafe extern "C" fn(Archive) -> c_int,
    open: unsafe extern "C" fn(Archive, c_int, usize) -> c_int,
    next: unsafe extern "C" fn(Archive, *mut Archive) -> c_int,
    data: unsafe extern "C" fn(Archive, *mut c_void, usize) -> isize,
    skip: unsafe extern "C" fn(Archive) -> c_int,
    error: unsafe extern "C" fn(Archive) -> *const c_char,
    name: unsafe extern "C" fn(Archive) -> *const c_char,
    size: unsafe extern "C" fn(Archive) -> i64,
    size_set: unsafe extern "C" fn(Archive) -> c_int,
    kind: unsafe extern "C" fn(Archive) -> c_uint,
    hardlink: unsafe extern "C" fn(Archive) -> *const c_char,
    symlink: unsafe extern "C" fn(Archive) -> *const c_char,
    encrypted: unsafe extern "C" fn(Archive) -> c_int,
}
impl Api {
    fn load() -> Result<Self, ScanError> {
        #[cfg(target_os = "linux")]
        let candidates = ["libarchive.so.13", "libarchive.so"];
        #[cfg(not(target_os = "linux"))]
        let candidates = ["/usr/lib/libarchive.dylib", "libarchive.dylib"];
        let library = candidates
            .iter()
            .find_map(|p| unsafe { libloading::Library::new(p) }.ok())
            .ok_or_else(|| blocked("libarchive could not be loaded"))?;
        // SAFETY: symbols and C signatures match libarchive's stable public API;
        // the owning Library stays alive until after archive_read_free.
        unsafe {
            macro_rules! load {
                ($name:literal) => {
                    *library
                        .get(concat!($name, "\0").as_bytes())
                        .map_err(|e| blocked(format!("libarchive symbol: {e}")))?
                };
            }
            Ok(Self {
                new: load!("archive_read_new"),
                free: load!("archive_read_free"),
                filter: load!("archive_read_support_filter_none"),
                rar: load!("archive_read_support_format_rar"),
                rar5: load!("archive_read_support_format_rar5"),
                zip: load!("archive_read_support_format_zip"),
                open: load!("archive_read_open_fd"),
                next: load!("archive_read_next_header"),
                data: load!("archive_read_data"),
                skip: load!("archive_read_data_skip"),
                error: load!("archive_error_string"),
                name: load!("archive_entry_pathname_utf8"),
                size: load!("archive_entry_size"),
                size_set: load!("archive_entry_size_is_set"),
                kind: load!("archive_entry_filetype"),
                hardlink: load!("archive_entry_hardlink"),
                symlink: load!("archive_entry_symlink"),
                encrypted: load!("archive_entry_is_encrypted"),
                _library: library,
            })
        }
    }
}
pub(super) struct Entry {
    pub name: String,
    pub size: Option<u64>,
    pub kind: u32,
    pub encrypted: bool,
    pub link: bool,
}
pub(super) struct Reader {
    api: Api,
    archive: Archive,
}
impl Reader {
    pub fn new(file: &mut File, format: Format) -> Result<Self, ScanError> {
        let api = Api::load()?;
        let archive = unsafe { (api.new)() };
        if archive.is_null() {
            return Err(blocked("libarchive allocation failed"));
        }
        let reader = Self { api, archive };
        reader.check(unsafe { (reader.api.filter)(archive) } as isize)?;
        let support = match format {
            Format::Zip => reader.api.zip,
            Format::Rar => reader.api.rar,
            Format::Rar5 => reader.api.rar5,
        };
        reader.check(unsafe { support(archive) } as isize)?;
        file.seek(SeekFrom::Start(0))?;
        reader.check(
            unsafe { (reader.api.open)(archive, file.as_raw_fd(), MIB as usize) } as isize,
        )?;
        Ok(reader)
    }
    fn check(&self, code: isize) -> Result<isize, ScanError> {
        if code < 0 {
            let p = unsafe { (self.api.error)(self.archive) };
            let message = if p.is_null() {
                "libarchive failed".into()
            } else {
                unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
            };
            return Err(blocked(message));
        }
        Ok(code)
    }
    pub fn next(&mut self) -> Result<Option<Entry>, ScanError> {
        let mut entry = std::ptr::null_mut();
        let result = self.check(unsafe { (self.api.next)(self.archive, &mut entry) } as isize)?;
        if result == 1 {
            return Ok(None);
        }
        if result != 0 || entry.is_null() {
            return Err(blocked("unexpected libarchive header result"));
        }
        unsafe {
            let name = (self.api.name)(entry);
            if name.is_null() {
                return Err(blocked("archive member has no UTF-8 name"));
            }
            let name = CStr::from_ptr(name)
                .to_str()
                .map_err(|_| blocked("archive name is invalid UTF-8"))?
                .to_owned();
            let size = (self.api.size)(entry);
            let size = if (self.api.size_set)(entry) != 0 && size >= 0 {
                Some(size as u64)
            } else {
                None
            };
            Ok(Some(Entry {
                name,
                size,
                kind: (self.api.kind)(entry),
                encrypted: (self.api.encrypted)(entry) != 0,
                link: !(self.api.hardlink)(entry).is_null() || !(self.api.symlink)(entry).is_null(),
            }))
        }
    }
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ScanError> {
        let n = self.check(unsafe {
            (self.api.data)(self.archive, buffer.as_mut_ptr().cast(), buffer.len())
        })?;
        if n as usize > buffer.len() {
            return Err(blocked("libarchive returned impossible byte count"));
        }
        Ok(n as usize)
    }
    pub fn skip(&mut self) -> Result<(), ScanError> {
        self.check(unsafe { (self.api.skip)(self.archive) } as isize)?;
        Ok(())
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        unsafe {
            (self.api.free)(self.archive);
        }
    }
}

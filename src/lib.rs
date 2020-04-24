//#![feature(const_fn)]

extern crate winapi;
use std::io::Error;

struct Vpdata
{
    mem : *mut winapi::ctypes::c_void,
    msize : usize,
    unp : bool,
    oldprotect : u32
}

pub fn add_as_fun_ptr<T>(fptr : &u32) -> &T
{
     unsafe { &*((fptr as *const u32) as *const T) }
}

impl Vpdata
{
    pub fn new<T>(ptr : *mut T, size : usize, usevp : bool) -> Vpdata
    {
        let mut protection : u32 = 0;
        let mut unprotected = false;
        if usevp
        {
            if size > 0
            {
                use winapi::um::memoryapi::VirtualProtect;
                unprotected = unsafe { VirtualProtect(ptr as *mut winapi::ctypes::c_void, size, winapi::um::winnt::PAGE_EXECUTE_READWRITE, &mut protection) != 0 };
			}
		}

        Vpdata {
            mem: ptr as *mut winapi::ctypes::c_void,
            msize: size,
            unp: unprotected,
            oldprotect: protection
		}
	}
}

impl Drop for Vpdata {
    fn drop(&mut self) {
        if self.unp
        {
            use winapi::um::memoryapi::VirtualProtect;
            unsafe { VirtualProtect(self.mem, self.msize, self.oldprotect, &mut self.oldprotect) };
		}
    }
}

pub fn it_works()
{
    assert_eq!(2 + 2, 4);
}

pub fn read_memory<T>(mem : *mut T, vp : bool) -> T
{
    let _scopevp = Vpdata::new(mem, std::mem::size_of::<T>(), vp);
    unsafe { std::ptr::read_unaligned(mem) }
}

pub fn write_memory<T>(mem : *mut T, val : T, vp : bool)
{
    let _scopevp = Vpdata::new(mem, std::mem::size_of::<T>(), vp);
    unsafe { std::ptr::write_unaligned(mem, val); }
}

pub fn get_absolute_offset<T>(rel_value : isize, mem : *mut T) -> *mut T
{
    unsafe { mem.offset(rel_value) }
}

pub fn get_relative_offset<T>(abs_value : *mut T, end_of_instruction : *mut T) -> isize
{
    let absv = abs_value as isize;
    let endofi = end_of_instruction as isize;
    absv - endofi
}

pub fn read_relative_offset<T>(mem : *mut T, sizeof_addr : usize, vp : bool) -> *mut T
{
    match sizeof_addr
    {
        1 => return get_absolute_offset::<T>(read_memory(mem as *mut i8, vp) as isize, unsafe { mem.add(sizeof_addr) }),
        2 => return get_absolute_offset::<T>(read_memory(mem as *mut i16, vp) as isize, unsafe { mem.add(sizeof_addr) }),
        4 => return get_absolute_offset::<T>(read_memory(mem as *mut i32, vp) as isize, unsafe { mem.add(sizeof_addr) }),
        _ => panic!("Unsupported size"),
	}
}

pub fn make_relative_offset<T>(at : *mut T, dest : *mut T, sizeof_addr : usize, vp : bool)
{
    match sizeof_addr
    {
        1 => write_memory(at as *mut i8, get_relative_offset(dest, unsafe { at.add(sizeof_addr) }) as i8, vp),
        2 => write_memory(at as *mut i16, get_relative_offset(dest, unsafe { at.add(sizeof_addr) }) as i16, vp),
        4 => write_memory(at as *mut i32, get_relative_offset(dest, unsafe { at.add(sizeof_addr) }) as i32, vp),
        _ => panic!("Unsupported size"),
	}
}

pub fn get_branch_destination<T>(mem : *mut T, vp : bool) -> *mut T
{
    match read_memory(mem as *mut u8, vp)
    {
        0xE8 | 0xE9 => return read_relative_offset(unsafe { mem.add(1) }, 4, vp),
        0xFF => println!("placeholder"),
        _ => println!("placeholder"),
	}
    0 as *mut T
}

pub fn make_call<T>(mem : *mut T, target : *mut T, vp : bool) -> *mut T
{
    let p = get_branch_destination(mem, vp);
    write_memory(mem as *mut u8, 0xE8, vp);
    make_relative_offset(unsafe { mem.add(1) }, target, 4, vp);
    p
}

pub fn make_jmp<T>(mem : *mut T, target : *mut T, vp : bool) -> *mut T
{
    let p = get_branch_destination(mem, vp);
    write_memory(mem as *mut u8, 0xE9, vp);
    make_relative_offset(unsafe { mem.add(1) }, target, 4, vp);
    p
}

pub fn make_ja<T>(mem : *mut T, target : *mut T, vp : bool) -> *mut T
{
    let p = get_branch_destination(mem, vp);
    write_memory(mem as *mut u16, 0x87F0, vp);
    make_relative_offset(unsafe { mem.add(2) }, target, 4, vp);
    p
}

pub fn print_message(msg: &str) -> Result<i32, Error> {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use winapi::um::winuser::{MB_OK, MessageBoxW};
    let wide: Vec<u16> = OsStr::new(msg).encode_wide().chain(once(0)).collect();
    let ret = unsafe {
        MessageBoxW(null_mut(), wide.as_ptr(), wide.as_ptr(), MB_OK)
    };
    if ret == 0 { Err(Error::last_os_error()) }
    else { Ok(ret) }
}

pub fn make_nop<T>(mut mem : *mut T, size : usize, vp : bool)
{
    let _scopevp = Vpdata::new(mem, size, vp);
    
    for _x in 0..size
    {
        unsafe {
            std::ptr::write_unaligned(mem as *mut u8, 0x90);
            mem = mem.add(1);
        }
    }
}

pub fn make_typed_nop<T>(mem : *mut T, count : usize, vp : bool)
{
    let _scopevp = Vpdata::new(mem, std::mem::size_of::<T>() * count, vp);
    
    unsafe {
        std::ptr::write_bytes(mem, 0x90, count);
    }
}

pub fn show_text_low_priority(msg : &str, time : u32, flag1 : bool, flag2 : bool)
{
    let ptr : u32 = 0x0069F0B0;
    let text_low_priority = add_as_fun_ptr::<extern "C" fn(*const u8, u32, bool, bool)>(&ptr);

    text_low_priority(msg.as_ptr(), time, flag1, flag2);
}

extern "C" fn mycb()
{
    show_text_low_priority("Pato pato anda\0", 100, false, false);
}

#[no_mangle]
pub extern "stdcall" fn DllMain(_: *const u8, fdw_reason: u32, _: *const u8) -> u32
{
    if fdw_reason == winapi::um::winnt::DLL_PROCESS_ATTACH
    {
        let ptr = 0x006AB344 as *mut u8;
        //make_nop(ptr, 5, true);
        //make_typed_nop(ptr, 5, true);

        let p = make_call(ptr, mycb as *mut u8, true) as u32;
        print_message(&p.to_string());
	}

    1
}

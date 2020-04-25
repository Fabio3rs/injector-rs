//#![feature(const_fn)]

extern crate winapi;
use std::io::Error;
mod injector;

pub fn show_text_low_priority(msg : &str, time : u32, flag1 : bool, flag2 : bool)
{
    let ptr : u32 = 0x0069F0B0;
    let text_low_priority = injector::injector::add_as_fun_ptr::<extern "C" fn(*const u8, u32, bool, bool)>(&ptr);

    text_low_priority(msg.as_ptr(), time, flag1, flag2);
}

extern "C" fn mycb(reg_pack : *mut injector::injector::RegPack)
{
    show_text_low_priority("Pato pato anda\0", 100, false, false);
}

#[no_mangle]
pub extern "stdcall" fn DllMain(_: *const u8, fdw_reason: u32, _: *const u8) -> u32
{
    if fdw_reason == winapi::um::winnt::DLL_PROCESS_ATTACH
    {
        injector::injector::make_inline(0x006AB344, mycb as *mut u8);
	}

    1
}

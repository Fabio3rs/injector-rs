//#![feature(const_fn)]

extern crate winapi;
mod injector;

#[allow(dead_code)]
struct GlobalData
{
    selcolor: i32,
    primarycolor: i32,
    secondarycolor: i32,
    selected: bool,
    jumped: bool,
    panel: std::option::Option::<u32>
}

impl GlobalData
{
    fn new() -> GlobalData
    {
        GlobalData
        {
            selcolor: 0,
            primarycolor: 0,
            secondarycolor: 0,
            selected: false,
            jumped: false,
            panel: None
		}
	}
}

static mut MODDATA: std::option::Option::<GlobalData> = None;

pub fn show_text_low_priority(msg : &str, time : u32, flag1 : bool, flag2 : bool)
{
    let ptr : u32 = 0x0069F0B0;
    let text_low_priority = injector::injector::add_as_fun_ptr::<extern "C" fn(*const u8, u32, bool, bool)>(&ptr);

    text_low_priority(msg.as_ptr(), time, flag1, flag2);
}

pub fn cscript_thread_get_player_key_state(a : u16, b : u16) -> bool
{
    let ptr : u32 = 0x00485B10;
    let get_player_key_state = injector::injector::add_as_fun_ptr::<extern "fastcall" fn(u32, u32, u16, u16) -> u16>(&ptr);

    get_player_key_state(0, 0, a, b) != 0
}

pub fn remove_panel(a : u32) -> bool
{
    let ptr : u32 = 0x00580750;
    let remove_panelp = injector::injector::add_as_fun_ptr::<extern "C" fn(u32) -> u8>(&ptr);

    remove_panelp(a) != 0
}

extern "C" fn mycb(_reg_pack : *mut injector::injector::RegPack, _oldfun : u32)
{
    let reg_pack = unsafe { &mut *_reg_pack };
    let current_time = unsafe { &*(0x00B7CB84 as *const u32) };

    if let Some(x) = unsafe { &mut MODDATA }
    {
        
        
        if cscript_thread_get_player_key_state(0, 15)
        {
            injector::injector::write_memory_iptr(reg_pack.esi + 77, 3 as u8, true);
            injector::injector::write_memory_iptr(reg_pack.esi + 60, current_time + 3000 as u32, true);

            if let Some(pn) = x.panel
            {
                remove_panel(pn);
                x.panel = None;
			}
		}
	}
}

fn inject()
{
    injector::injector::make_jmp((0x0044AEC0 + 5) as *mut u8, 0x0044B3FF as *mut u8, true);
	
	injector::injector::make_nop(0x0044AE39 as *mut u8, 13, true);
	injector::injector::make_nop(0x0044AE4A as *mut u8, 5, true);

    injector::injector::make_inline(0x0044AEC0, mycb as *mut u8);
}

#[no_mangle]
pub extern "stdcall" fn DllMain(_: *const u8, fdw_reason: u32, _: *const u8) -> u32
{
    if fdw_reason == winapi::um::winnt::DLL_PROCESS_ATTACH
    {
        inject();

        if let Some(_x) = unsafe { &mut MODDATA }
        {
            
		}else
        {
            unsafe { MODDATA  = Some(GlobalData::new()); }
		}
	}

    1
}

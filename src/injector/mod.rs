//#![feature(const_fn)]

//mod dllmain;

pub mod injector
{
    #![allow(dead_code)]
    extern crate winapi;

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

    #[allow(dead_code)]
    #[repr(packed(1))]
    pub struct RegPack {
        // PUSHFD / POPFD
        pub ef: u32,
        // PUSHAD/POPAD -- must be the lastest fields (because of esp)
        pub edi: u32,
        pub esi: u32,
        pub ebp: u32,
        pub esp: u32,
        pub ebx: u32,
        pub edx: u32,
        pub ecx: u32,
        pub eax: u32,
        // RET ADDRESS
        pub retn: u32,
    }

    #[allow(dead_code)]
    #[repr(packed(1))]
    pub struct InlineCode
    {
        pushad: u8,
        add: u8,
        data: u32,

        pushfd: u8,
        pushesp: u8,

        push: u8,
        pushaddr: u32,

        push2: u8,
        oldcalladdr: u32,

        call: u8,
        addr: u32,

        addesp: u16,
        addespnum: u8,

        sub: u8,
        data1: u32,

        popfd: u8,
        popad: u8,

        retn: u8,
        retnsiz: u16,
    }

    static mut INLINE_LIST: std::option::Option<std::collections::VecDeque<InlineCode>> = None;

    impl InlineCode
    {
        fn new() -> InlineCode
        {
            InlineCode{
				    pushad: 0x60,				// pushad
				    add: 0x80, data: 0x040C2444,  // add[esp + 12], 4 
				    pushfd: 0x9C,				 // pushfd

				    pushesp: 0x54,			   // push esp

				    push: 0x68, pushaddr: 0,      // push address
                    push2: 0x68, oldcalladdr: 0x00,         // push <retnaddr>
				    //0x68, uintptr_t(c), // push c
				    //0x68, 0x00,         // push <retnaddr>

				    call: 0xE8, addr: 0x00,			// call callwrapper

				    addesp: 0xC483, addespnum: 12,		// add esp, 12

				    sub: 0x80, data1: 0x0410246C, // sub[esp + 12 + 4], 4

				    popfd: 0x9D,				// popfd
				    popad: 0x61,				// popad
				    retn: 0xC2, retnsiz: 0x00			// retn x
			    }
	    }
    }

    pub fn offset_of<T,C>(start: *const T, end: *const C) -> isize
    {
        get_relative_offset(start as *const u8, end as *const u8)
    }

    pub fn address_of<T>(var : *const T) -> usize
    {
        var as usize
    }

    extern "C" fn make_inline_wrapper(oldcalladdr : u32, funptr : u32, reg_pack : *mut RegPack)
    {
        let foo = add_as_fun_ptr::<extern "C" fn(*mut RegPack, u32)>(&funptr);
        foo(reg_pack, oldcalladdr);
    }

    pub fn make_inline<T>(addr : u32, target : *mut T)
    {
        if let Some(_x) = unsafe { &mut INLINE_LIST }
        {
            
		}else
        {
            unsafe { INLINE_LIST  = Some(std::collections::VecDeque::<InlineCode>::new()); }
		}

        match unsafe { &mut INLINE_LIST }
        {
            Some(x) => {
                x.push_back(InlineCode::new());
            
                {
                    if let Some(el) = x.back_mut()
                    {
                        make_call(address_of(&el.call) as *mut u8, make_inline_wrapper as *mut u8, true) as u32;
                        el.pushaddr = target as u32;

                        el.oldcalladdr = make_call(addr as *mut u8, address_of(el) as *mut u8, true) as u32;
			        }     
			    }
            },
            None => { let _ = print_message("INLINE_LIST is None"); },
	    }
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

    pub fn write_memory_iptr<T>(mem : u32, val : T, vp : bool)
    {
        write_memory(mem as *mut T, val, vp);
	}

    pub fn get_absolute_offset<T>(rel_value : isize, mem : *mut T) -> *mut T
    {
        unsafe { mem.offset(rel_value) }
    }

    pub fn get_relative_offset<T>(abs_value : *const T, end_of_instruction : *const T) -> isize
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

    pub fn print_message(msg: &str) -> Result<i32, std::io::Error> {
        use std::ffi::OsStr;
        use std::iter::once;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::null_mut;
        use winapi::um::winuser::{MB_OK, MessageBoxW};
        let wide: Vec<u16> = OsStr::new(msg).encode_wide().chain(once(0)).collect();
        let ret = unsafe {
            MessageBoxW(null_mut(), wide.as_ptr(), wide.as_ptr(), MB_OK)
        };
        if ret == 0 { Err(std::io::Error::last_os_error()) }
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
}

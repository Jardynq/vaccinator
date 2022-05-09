#![cfg(windows)]

use winapi::shared::minwindef::*;
use winapi::um::winnt::*;
use winapi::um::winuser::*;
use winapi::um::psapi::*;
use winapi::um::libloaderapi::*;
use winapi::um::processthreadsapi::*;


// Advanced dll image for testing


#[allow(non_snake_case)]
#[no_mangle]
extern "system" fn DllMain(module: HINSTANCE, reason: DWORD, _: LPVOID) -> BOOL {
	let headers = unsafe {
		let host = GetModuleHandleA(0 as _);
		pe_image::PeHeaders::read_buffer(host, None, 0).unwrap()
	};
	let host_arch = match headers.file_header.machine {
		pe_image::ImageFileMachine::Amd64 => "x64",
		pe_image::ImageFileMachine::I386 => "x86",
		_ => "unknown arch",
	};
	#[cfg(target_arch = "x86_64")]
	let self_arch = "x64";
	#[cfg(target_arch = "x86")]
	let self_arch = "x86";


	let name_buffer: std::mem::MaybeUninit<[u16; MAX_PATH]> = std::mem::MaybeUninit::zeroed();
	unsafe {
		GetModuleFileNameExW(GetCurrentProcess(), 0 as _, std::mem::transmute(&name_buffer), MAX_PATH as u32);
	}

	let mut terminated = false;
	let name: Vec<u16> = unsafe {
		name_buffer.assume_init().iter()
			.filter_map(|c| {
				if *c == 0 {
					terminated = true;
				}
				if !terminated {
					Some(*c as u16)
				} else {
					None
				}
			})
			.collect()
	};
	let name_string = String::from_utf16( name.as_slice() ).unwrap_or("* Failed to get name of process *".to_string());

	let cpu_mode = nt_syscall::cpu_mode!();
	let message = format!("Located at: {:p}\nCpu mode is {:?}\nHost is {}\nImage is {}\nHello from inside:\n{}\0", module, cpu_mode, host_arch, self_arch, name_string);

    match reason {
        DLL_PROCESS_ATTACH => {
			let caption = "+ Attach\0";
			unsafe {
				MessageBoxA(0 as _, message.as_ptr() as _, caption.as_ptr() as _, MB_OK);
			}
		}
        DLL_PROCESS_DETACH => {
			let caption = "- Detach\0";
			unsafe {
				MessageBoxA(0 as _, message.as_ptr() as _, caption.as_ptr() as _, MB_OK);
			}
		}
        _ => ()
    }
	
	TRUE
}

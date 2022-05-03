#![feature(asm)]
#![feature(unchecked_math)]

use std::mem::{
	transmute,
	size_of,
};

use interface::*;

use ntapi::ntpsapi::PEB_LDR_DATA;
use ntapi::ntrtl::RTL_RB_TREE;
use winapi::shared::minwindef::*;
use winapi::um::winbase::GetCurrentActCtx;
use winapi::um::winnt::*;
use winapi::shared::ntdef::{LIST_ENTRY, RTL_BALANCED_NODE, SINGLE_LIST_ENTRY};
use winapi::um::memoryapi::*;
use winapi::um::errhandlingapi::*;
use winapi::um::wow64apiset::*;

use nt_syscall::*;

use ntapi::ntldr::*;
use winapi::um::tlhelp32::*;
use winapi::um::handleapi::*;


mod debug;
mod state;
use state::StateAbstract;





unsafe extern "system" fn threadad(param: *mut VOID) -> DWORD {
	println!("PARAM: {:p}", param);
	loop {
		print!("a");
		std::thread::sleep(std::time::Duration::from_millis(10));
	}
}

pub fn sz_to_str(sz: &Vec<i8>) -> String {
    let mut terminated = false;
    String::from_utf8(
        sz.into_iter()
            .filter_map(|c| {
                if *c == 0 {
                    terminated = true;
                }
                if !terminated {
                    Some(*c as u8)
                } else {
                    None
                }
            })
            .collect()
    ).unwrap_or(format!(""))
}

pub fn enumerate_threads(pid: Option<DWORD>, callback: &mut dyn FnMut(&THREADENTRY32) -> bool) {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let mut entry = THREADENTRY32 {
		dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
		cntUsage: 0,
		th32ThreadID: 0,
		th32OwnerProcessID: 0,
		tpBasePri: 0,
		tpDeltaPri: 0,
		dwFlags: 0,
	};

    if unsafe { Thread32First(snapshot, &mut entry) } == TRUE {
        loop {
            if let Some(pid) = pid {
                if pid != entry.th32OwnerProcessID {
					if unsafe { Thread32Next(snapshot, &mut entry) } == FALSE {
						break;
					} else {
						continue;
					}
                }
            }
            if callback(&entry) {
                unsafe {
                   CloseHandle(snapshot);
                }
                break;
            }
            if unsafe { Thread32Next(snapshot, &mut entry) } == FALSE {
                break;
            }
        }
    }
}

pub fn enumerate_processes(callback: &mut dyn FnMut(&PROCESSENTRY32) -> bool) {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let mut entry = PROCESSENTRY32 {
		dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
		cntUsage: 0,
		th32ProcessID: 0,
		th32DefaultHeapID: 0,
		th32ModuleID: 0,
		cntThreads: 0,
		th32ParentProcessID: 0,
		pcPriClassBase: 0,
		dwFlags: 0,
		szExeFile: [0; MAX_PATH],
	};

    if unsafe { Process32First(snapshot, &mut entry) } == TRUE {
        loop {
            if callback(&entry) {
                unsafe {
                   CloseHandle(snapshot);
                }
                break;
            }
            if unsafe { Process32Next(snapshot, &mut entry) } == FALSE {
                break;
            }
        }
    }
}



macro_rules! link_module  {
	($( $head:expr )*, $( $entry:expr )*) => {
		let head: *mut LIST_ENTRY = $( $head )*;
		let tail = head.read().Blink;
		let entry: *mut LIST_ENTRY = $( $entry )*;

		entry.write(::winapi::shared::ntdef::LIST_ENTRY {
			Flink: head,
			Blink: tail,
		});
		head.write(LIST_ENTRY{
			Flink: head.read().Flink,
			Blink: transmute(entry),
		});
		tail.write(LIST_ENTRY{
			Flink: transmute(entry),
			Blink: tail.read().Blink,
		});
	}
}


macro_rules! unistring {
	($( $uni:expr )*) => {{
		let uni = $($uni)*;
		let ptr = uni.Buffer.cast::<u8>();
		let length = uni.Length;
		
		let mut result = Vec::new();
		for offset in 0..(length as isize) {
			result.push(ptr.offset(offset).read());
		}

		String::from_utf8(result).unwrap()
	}}
}

macro_rules! ddd {
	($($reff:expr)*) => {{
		let reff: &LDR_DATA_TABLE_ENTRY = $($reff)*;

		// TODO: when init set some of the members to randoim values to thort defnece
		log::info!("self         \t{:p}", reff);
		log::info!("load         \t{:p}, {:p}", reff.InLoadOrderLinks.Flink, reff.InLoadOrderLinks.Blink);
		log::info!("mem          \t{:p}, {:p}", reff.InMemoryOrderLinks.Flink, reff.InMemoryOrderLinks.Blink);
		log::info!("init         \t{:p}, {:p}", reff.u1.InInitializationOrderLinks.Flink, reff.u1.InInitializationOrderLinks.Blink);
		log::info!("base         \t{:p}", reff.DllBase);
		log::info!("entry        \t{:p}", transmute::<_, *const u8>(reff.EntryPoint));
		log::info!("size         \t{:x}", reff.SizeOfImage);
		log::info!("full_name    \t{}", unistring!(reff.FullDllName));
		log::info!("base_name !  \t{}", unistring!(reff.BaseDllName));
		log::info!("flags        \t{:x}, {:x}, {:x}, {:x}", reff.u2.FlagGroup[0], reff.u2.FlagGroup[1], reff.u2.FlagGroup[2], reff.u2.FlagGroup[3]);
		log::info!("obs_count    \t{:x}", reff.ObsoleteLoadCount);
		log::info!("tls_index    \t{:x}", reff.TlsIndex);
		log::info!("hash_link    \t{:p}, {:p}", reff.HashLinks.Flink, reff.HashLinks.Blink);
		log::info!("time         \t{:x}", reff.TimeDateStamp);
		log::info!("actv_ctx     \t{:p}", reff.EntryPointActivationContext);
		log::info!("lock         \t{:p}", reff.Lock);
		log::info!("ddag         \t{:p}", reff.DdagNode);
		log::info!("node_link    \t{:p}, {:p}", reff.NodeModuleLink.Flink, reff.NodeModuleLink.Blink);
		log::info!("load_ctx     \t{:p}", reff.LoadContext);
		log::info!("parent       \t{:p}", reff.ParentDllBase);
		log::info!("switch_ctx   \t{:p}", reff.SwitchBackContext);
		/*
		BaseAddressIndexNode: RTL_BALANCED_NODE,
		MappingInfoIndexNode: RTL_BALANCED_NODE,
		*/
		log::info!("orig_base    \t{:x}", reff.OriginalBase);
		log::info!("load_time    \t{:x}", transmute::<_, i64>(reff.LoadTime));
		log::info!("name_hash    \t{:x}", reff.BaseNameHashValue);
		log::info!("reason       \t{:x}", reff.LoadReason);
		log::info!("implicit     \t{:x}", reff.ImplicitPathOptions);
		log::info!("ref_count    \t{:x}", reff.ReferenceCount);
		log::info!("dep_flags    \t{:x}", reff.DependentLoadFlags);
		log::info!("signing      \t{:x}", reff.SigningLevel);
	}}
}



// https://www.deepinstinct.com/2019/07/24/inject-me-x64-injection-less-code-injection/


macro_rules! hash {
	( StringU8 = $( $string:expr )* , $($pass:tt)* ) => {
		hash!( $( $string )* as *const u8, $($pass)* )
	};
	( StringU16 = $( $string:expr )* , $($pass:tt)* ) => {
		hash!( $( $string )* as *const u16, $($pass)* )
	};
	( String = $( $string:expr )* , $($pass:tt)* ) => {{
		match $( $string )* {
			::interface::CString::U8(string) => {
				hash!(StringU8 = string, $($pass)* )
			}
			::interface::CString::U16(string) => {
				hash!(StringU16 = string, $($pass)* )
			}
		}
	}};
	( $( $string:expr )*, $( $uppercase:expr )* $(, Length = $( $length:expr )* )? $(, Token[ $( $( $end:expr )* ),* ] )? ) => {{
		let mut string = $($string)*;
		let mut hash: u64 = 0;
		
		let mut _count = 0;
		while true $( && _count < ($($length)*) )? $( $( && string.read() != (($($end)*) as _) )* )? {
			let mut character = string.read() as u64;
			if $($uppercase)* {
				if character <= 'z' as _ && character >= 'a' as _ {
					character -= 0x20
				}
			}
			hash = character.wrapping_add((hash << 6)).wrapping_add(hash << 16).wrapping_sub(hash);
			string = string.offset(1);
			_count += 1;
		}
		hash
	}};
}





#[no_mangle]
pub unsafe fn parse_header(module: usize) -> Option<(usize, usize)> {
	if module == 0 {
		return None;
	}

	let dos: &IMAGE_DOS_HEADER = transmute(module);
	if dos.e_magic != IMAGE_DOS_SIGNATURE {
		return None;
	}

	let nt: &IMAGE_NT_HEADERS = transmute(module + dos.e_lfanew as usize);
	if nt.Signature != IMAGE_NT_SIGNATURE {
		return None;
	}

	#[cfg(target_arch = "x86_64")]
	let (magic, machine) = (
		nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC,
		nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64
	);
	#[cfg(target_arch = "x86")]
	let (magic, machine) = (
		nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC,
		nt.FileHeader.Machine == IMAGE_FILE_MACHINE_I386
	);

	if !magic {
		return None;
	}
	if !machine {
		return None;
	}

	let address = transmute::<_, usize>(nt);
	let sections = module + dos.e_lfanew as usize + size_of::<u32>() + size_of::<IMAGE_FILE_HEADER>() + nt.FileHeader.SizeOfOptionalHeader as usize;

	Some((address, sections))
}

unsafe fn test(module_p: usize, data_p: &mut LDR_DATA_TABLE_ENTRY, module_name_p: String) {
	let mut tree_root = 0;


	let ldr_data = transmute::<_, &mut PEB_LDR_DATA>(peb!().Ldr);
	let head_load =   (&mut ldr_data.InLoadOrderModuleList) as *mut LIST_ENTRY;
	let head_memory =   (&mut ldr_data.InMemoryOrderModuleList) as *mut LIST_ENTRY;
	let head_initialization =   (&mut ldr_data.InInitializationOrderModuleList) as *mut LIST_ENTRY;

	// I could check by comparing the name, but if this entry isn't ntdll, then something is real bad
	let ntdll_entry: &mut LDR_DATA_TABLE_ENTRY = transmute(head_memory.read().Flink.read().Flink.offset(-1));
	let ntdll_module: *mut u8 = ntdll_entry.DllBase.cast();


	// Find the root node, by traversing upwards
	let mut index_node: &mut RTL_BALANCED_NODE = &mut ntdll_entry.BaseAddressIndexNode;
	loop {
		// The first three bits of the parent value are used as flags
		// The other are a pointer to the parent
		let next_index = index_node.ParentValue & !0b111;
		if next_index == 0 {
			break;
		}

		index_node = transmute(next_index);
	}
	let node_address: usize = transmute(index_node as *mut _);


	// The first bit of the parent value is whether it's red (1) or black (0)
	// The root node is always black
	let is_black = (index_node.ParentValue & 0b1) == 0;
	if is_black {
		let (nt, sections) = match parse_header(ntdll_module as usize) {
			Some((address, sections)) => (
				transmute::<_, &IMAGE_NT_HEADERS>(address),
				transmute::<_, *mut IMAGE_SECTION_HEADER>(sections)
			),
			None => {
				return;
			}
		};


		// Grab the .data section from ntdll since that's where the tree resides
		'outer: for index in 0..nt.FileHeader.NumberOfSections {
			let section: &mut IMAGE_SECTION_HEADER = transmute(sections.offset(index as isize));
			
			if {
				section.Name[0] == '.' as u8 &&
				section.Name[1] == 'd' as u8 &&
				section.Name[2] == 'a' as u8 &&
				section.Name[3] == 't' as u8 &&
				section.Name[4] == 'a' as u8 &&
				section.Name[5] == 0 &&
				section.Name[6] == 0 &&
				section.Name[7] == 0
			} {
				let section_base = ntdll_module.offset(section.VirtualAddress as isize);
				let section_size = *section.Misc.VirtualSize() as isize;

				// search .data for a pointer that points to the node from the PEB
				for offset in (0..section_size).step_by(size_of::<usize>()) {
					let pointer = section_base.offset(offset).cast::<usize>();
					if pointer.read() == node_address {
						let tree: &mut RTL_RB_TREE = transmute(pointer);

						if !tree.Root.is_null() && !tree.Min.is_null() {
							// EVERY THING IS GOOCH
							tree_root = tree as *const _ as usize;
							break 'outer;
						}
					}
				}
			}
		}
	} else {
		// RedBlackRootIsNotBlack
	}


	let mut data = data_p;
	let module = module_p;

	let mut module_name = module_name_p;


	// Fill out known fields
	data.BaseDllName.Length = (module_name.len() * 2) as u16;
	data.BaseDllName.MaximumLength = (module_name.len() * 2) as u16;
	data.BaseDllName.Buffer = module_name.as_mut_ptr().cast();
	data.FullDllName.Length = (module_name.len() * 2) as u16;
	data.FullDllName.MaximumLength = (module_name.len() * 2) as u16;
	data.FullDllName.Buffer = module_name.as_mut_ptr().cast();
	data.DllBase = module as _;
	data.BaseNameHashValue = 0;
	data.SizeOfImage = 0x0000011;
	data.OriginalBase = module as _;
	data.EntryPoint = None;
	data.LoadReason = LoadReasonDynamicLoad as _;
	data.LoadTime = transmute(timestamp!());
	data.TlsIndex = -1i32 as _;
	data.ReferenceCount = -1i32 as _;
	//data.u2 = zeroed();
	data.u2.set_ImageDll(1);
	data.u2.set_LoadNotificationsSent(1);
	data.u2.set_TelemetryEntryProcessed(1);
	data.u2.set_LoadConfigProcessed(1);
	data.u2.set_EntryProcessed(1);
	data.u2.set_DontCallForThreads(1);
	data.u2.set_ProcessAttachCalled(1);
	data.u2.set_Redirected(1);
	data.u2.set_InIndexes(1);
	data.u2.set_InLegacyLists(1);
	data.u2.set_ProtectDelayLoad(1);
	data.u2.set_InIndexes(1);

	let ddddd = LDR_DDAG_NODE {
		Modules: std::mem::zeroed(),
		ServiceTagList: std::mem::zeroed(),
		LoadCount: 0xffff_ffff,
		LoadWhileUnloadingCount: std::mem::zeroed(),
		LowestLink: std::mem::zeroed(),
		u: std::mem::zeroed(),
		IncomingDependencies: std::mem::zeroed(),
		State: std::mem::zeroed(),
		CondenseLink: std::mem::zeroed(),
		PreorderNumber: std::mem::zeroed(),
	};

	data.DdagNode = transmute(&ddddd);


	
	log::info!("{:x}", tree_root);

	let tree_offset = memoffset::offset_of!(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode);
	log::info!("{:x}", tree_offset);



	// Walk down the tree until we find an empty leaf, to put our module
	let mut parent: &mut LDR_DATA_TABLE_ENTRY = transmute(tree_root as usize - tree_offset);
	loop {
		let mut is_right = false;
		let mut child = 0 as _;
		if module < parent.DllBase as usize {
			// Go left
			log::info!("going left");
			child = parent.BaseAddressIndexNode.u.s().Left;
			is_right = false;
		} else if module > parent.DllBase as usize {
			// Go Right
			log::info!("going right");
			child = parent.BaseAddressIndexNode.u.s().Right;
			is_right = true;
		} else {
			// Node is already inserted
			log::info!("going nowhere");
			// Let's overwrite whatever is here >:)
		}

		if child.is_null() {
			// Reached a leaf, time to insert here
			if is_right {
				let right = parent.BaseAddressIndexNode.u.s_mut().Right as usize;
				if right == 0 {
					log::info!("{:p}", parent.BaseAddressIndexNode.u.s_mut().Right);
					parent.BaseAddressIndexNode.u.s_mut().Right = transmute(&data.BaseAddressIndexNode);
					log::info!("Placing right");
				}
				else {
					log::info!("Colliding right");
				}
			} else {
				let left = parent.BaseAddressIndexNode.u.s_mut().Left as usize;
				if left == 0 {
					parent.BaseAddressIndexNode.u.s_mut().Left = transmute(&data.BaseAddressIndexNode);
					log::info!("Placing left");
				}
				else {
					log::info!("Colliding left");
				}
			}

			// The child has the opposite color of the parent, I assume same balance though
			let parent_address = &parent.BaseAddressIndexNode as *const _ as usize;
			let parent_balance = parent.BaseAddressIndexNode.ParentValue & 0b110;
			let parent_color = parent.BaseAddressIndexNode.ParentValue & 0b001;
			data.BaseAddressIndexNode.ParentValue = parent_address;
			data.BaseAddressIndexNode.ParentValue |= parent_balance;
			data.BaseAddressIndexNode.ParentValue |= (!parent_color) & 0b001;

			log::info!("poggers");
			break;
		}

		parent = transmute(child as usize - tree_offset);
	}





	let mut buffer = ".".repeat(1000);
	
	let mut temp = String::new();
	std::io::stdin().read_line(&mut temp);

	let error = winapi::um::libloaderapi::GetModuleFileNameA(module as _, buffer.as_mut_ptr() as _, 1000 - 3);
	log::warn!("{:x}", error);
	log::warn!("{:x}", teb!().LastErrorValue);
	log::warn!("{:x}", teb!().LastStatusValue);
	log::info!("{}", buffer);

	log::warn!("test");
}




fn main() {
	debug::initialize_logger();


	unsafe {
		println!("build: {}", nt_syscall::peb!().OSBuildNumber);

		let mod_name = "A\0A\0A\0A\0A\0A\0A\0A\0A\0A\0A\0A\0".to_string();
		let mut data: LDR_DATA_TABLE_ENTRY = std::mem::zeroed();
		//test(1, &mut data, mod_name);
	}

	log::warn!("test");
	//return;




	let ordinals = nt_syscall::ordinal!(
		NtWriteVirtualMemory, 
		NtAllocateVirtualMemory
	);
	if !ordinal_valid!(ordinals) {
		println!("Windows build not supported");
		return;
	}
	let wpm_ord = ordinals[0];
	let alloc_ord = ordinals[1];


	// TODO: the handle is invalid when target is spawned as child (from a debugger)

    let pid = {
        let mut pid = None;
        enumerate_processes(&mut |entry| {
            // Use hashing instead
            if "program.exe" == sz_to_str(&entry.szExeFile.to_vec()) {
            //if "notepad.exe" == sz_to_str(&entry.szExeFile.to_vec()) {
                pid = Some(entry.th32ProcessID);
                true
            } else {
                false
            }
		});
		match pid {
			Some(pid) => pid,
			None => {
				println!("Not found");
            	return;
			}
		}
    };
	println!("Found");

	let tid = {
		let mut tid = None;
		enumerate_threads(Some(pid), &mut |entry| {
			tid = Some(entry.th32ThreadID);
			true
		});
		match tid {
			Some(tid) => tid,
			None => {
				println!("Thread not available");
            	return;
			}
		}
	};




	let process = if cfg!(debug_assertions) {
		unsafe { winapi::um::processthreadsapi::OpenProcess(PROCESS_ALL_ACCESS, 0, pid) }
		//NtCurrentProcess
	} else {
		unsafe { winapi::um::processthreadsapi::OpenProcess(PROCESS_ALL_ACCESS, 0, pid) }
	};


	let is_image_x64 = false;

	let image: Vec<u8> = if is_image_x64 {
		include_bytes!("../shared/x86_64/test/image.dll").to_vec()
	} else {
		include_bytes!("../shared/i686/test/image.dll").to_vec()
	};

	let headers = pe_image::PeHeaders::read(&image, 0).unwrap();
	let optional_base;
	let image_size;
	let header_size;
	match &headers.optional_header {
		pe_image::OptionalHeader::Pe32(header) => {
			optional_base = header.image_base as u64;
			image_size = header.size_of_image as u64;
			header_size = header.size_of_headers as u64;
		},
		pe_image::OptionalHeader::Pe32Plus(header) => {
			optional_base = header.image_base as u64;
			image_size = header.size_of_image as u64;
			header_size = header.size_of_headers as u64;
		},
		_ => {
			println!("Could not parse headers");
			return;
		},
	};


	let mut is_wow64 = 0;
	unsafe {
		IsWow64Process(process, &mut is_wow64 as *mut _);
	}
	let mode;
	if headers.file_header.machine == pe_image::ImageFileMachine::Amd64 {
		if is_wow64 > 0 {
			mode = Mode::X64IntoX86Emulated;
		} else {
			mode = Mode::X64IntoX64Native;
		}
	} else if headers.file_header.machine == pe_image::ImageFileMachine::I386 {
		if is_wow64 > 0 {
			mode = Mode::X86IntoX86Emulated;
		} else {
			mode = Mode::X86IntoX64Native;
		}
	} else {
		println!("wierd image");
		return;
	}

	println!("MODE: {:?}", mode);

	let allocate_high = true;
	let mut zero_bits = 0;
	let mut alloc_type = MEM_COMMIT | MEM_RESERVE;
	if allocate_high {
		alloc_type |= MEM_TOP_DOWN;
	} else {
		#[cfg(target_arch = "x86_64")] {
			zero_bits = u32::MAX >> 4;
		}
		// TODO: verify this thing??
		// It alos does not work in 32bit
	};


	// try allocating at a high address TODO:
	let base = unsafe {
		let mut base = optional_base as *const u8;

		let size: u64 = image_size;

		let status = nt_syscall::syscall!(
			alloc_ord,
			process,
			&base as *const _,
			zero_bits,
			&size as *const _,
			alloc_type,
			PAGE_READWRITE
		);
		println!("status: {:x}", status);
		if base.is_null() || status != 0 {
			base = 0 as _;
			let status = nt_syscall::syscall!(
				alloc_ord,
				process,
				&base as *const _,
				zero_bits,
				&size as *const _,
				alloc_type,
				PAGE_EXECUTE_READWRITE
			);
			println!("status: {:x}", status);
		}


		println!("base: {:p}", base);
		if mode == Mode::X86IntoX64Native || mode == Mode::X86IntoX86Emulated {
			if base as u64 > u32::MAX as u64 {
				println!("base allocated WAYYYYY TOOO HIGH for x86");
				return;
			}
		}
		if base.is_null() {
			println!("Could not allocate\n{:x}", GetLastError());
			return;
		}

		base
	};



	// try allocation debug buffer
	const debug_size: usize = 0x10000000;
	let debug_buffer = unsafe {
		let mut debug_buffer = 0 as *const u8;
		let size = debug_size;
		let status = nt_syscall::syscall!(
			alloc_ord,
			process as usize,
			&mut debug_buffer as *mut _,
			zero_bits,
			&size as *const _,
			alloc_type,
			PAGE_EXECUTE_READWRITE
		);
		println!("debug status: {:x}", status);
		println!("debug bufffer: {:p}", debug_buffer);
		debug_buffer
	};




	unsafe {
		if WriteProcessMemory(process, base as _, image.as_ptr() as _, header_size as _, 0 as _) == FALSE {
			println!("Could not write headers\n{:x}", GetLastError());
			return;
		}
	}
	

	// TODO strip section name ".text" etc
	println!("image_base: {:p}", base);
	for section in headers.section_table.entries {
		unsafe {
			let address = base.offset(section.virtual_address as isize) as u64;
			let mut raw_size = section.size_of_raw_data;
			if raw_size == 0 {
				if section.characteristics.cnt_initialized_data {
					raw_size = headers.coff_header.size_of_initialized_data;
				}
				else if section.characteristics.cnt_uninitialized_data {
					raw_size = headers.coff_header.size_of_uninitialized_data;
				}
				else {
					continue;
				}
			}

			// Batch the wpm into a single call
			println!("{}: {:#?}", section.string_name(), base.offset(section.virtual_address as isize));
			if WriteProcessMemory(process, address as _, image.as_ptr().offset(section.pointer_to_raw_data as isize) as _, section.size_of_raw_data as usize, 0 as _) == FALSE {
				println!("Could not write section");
				return;
			}
		}
	}

	let cache_length = 0x200;
	let link_size = 0x10000;
	let shared_state_size = std::mem::size_of::<State>() + std::mem::size_of::<CacheEntry>() * cache_length + link_size;
	//if loader_data_size > opt.header_size then retyurn
	

	let mut shared_state = State::new(base as u64, cache_length as u32, link_size as u32, None, Some(debug_buffer as usize as u64), vec![])
		.expect("invalid windows version");
	let binary = shared_state.initialize_binary(true, mode);

	let shared_base= unsafe {
		let size = binary.len() + shared_state_size;
		let mut loader_base = 0 as *const u8;
		nt_syscall::syscall!(
			alloc_ord,
			process as usize,
			&mut loader_base as *mut _,
			zero_bits,
			&size as *const _,
			alloc_type,
			PAGE_EXECUTE_READWRITE
		);

		WriteProcessMemory(process, loader_base as _, &shared_state as *const State as _, std::mem::size_of::<State>() as _, 0 as _);
		WriteProcessMemory(process, loader_base.offset(shared_state_size as isize) as _, binary.as_ptr() as _, binary.len() as _, 0 as _);

		loader_base
	};


	let entry_point = match mode {
		Mode::X64IntoX64Native | Mode::X86IntoX86Native | Mode::X86IntoX86Emulated => {
			shared_base as u64 + shared_state.entry as u64
		}
		_ => {
			shared_base as u64 + shared_state.heavens_gate as u64
		}
	};

	eprintln!("{:x}", shared_base as usize);
	eprintln!("{:x}", entry_point as usize);
	let mut temp = String::new();
	eprintln!("exec?");
	std::io::stdin().read_line(&mut temp);


	// TODO:
	// TODO:
	// TODO:
	// TODO:
	// The reason i cant load gdi32.dll is because it uses winapi to find gdi32full.dll
	// It looks through the peb, so i need to link som dlls into, for support.
	// A way is to dependency walk (in the injector) and manaully choose which ones to link.
	// This will also cause issues for cross injection, since any winapi will look into peb and find wrong dlls.



	unsafe {
		let mut unused = 0_u32;
		winapi::um::processthreadsapi::CreateRemoteThread(process, 0 as _, 0, Some(std::mem::transmute(entry_point as usize)), shared_base as _, 0, &mut unused as _);
	}

	println!("dumb debug?");
	std::thread::sleep(std::time::Duration::from_millis(500));
	//std::io::stdin().read_line(&mut temp);


	// TODO:_ dealloc fo file_buffer gives c00000a0: mem not allocated, fix that

	loop {
		let buffer = unsafe {
			let buffer = vec![0; debug_size];
			ReadProcessMemory(process, debug_buffer as _, buffer.as_ptr() as _, debug_size as _, 0 as _);
			buffer
		};
		debug::debug(buffer, true);

		std::io::stdin().read_line(&mut temp);
	}
}

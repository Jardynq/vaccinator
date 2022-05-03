#![no_std]
#![feature(lang_items)]
#![feature(asm)]
#![cfg(windows)]

mod no_std {
	// Just to make the compiler shuts up and actualy show me relevant errors
	#![cfg(feature = "build")]

	#[lang = "eh_personality"]
	extern fn rust_eh_personality() {  }
	
	#[panic_handler]
	fn panic(_: &core::panic::PanicInfo) -> ! { loop { } }
	
	#[allow(non_snake_case)]
	#[no_mangle]
	extern "system" fn _DllMainCRTStartup(_: usize, _: u32, _: *const ()) -> u32 { 1 }
}




use core::mem::{
	MaybeUninit,
	transmute,
	size_of,
};
use memoffset::offset_of;

use ntapi::{
	ntexapi::KUSER_SHARED_DATA,
	ntrtl::{
		RTL_USER_PROCESS_PARAMETERS,
		RTL_RB_TREE,
	},
	ntldr::{
		LDR_DATA_TABLE_ENTRY,
		LoadReasonDynamicLoad,
		LdrModulesReadyToRun,
	},
	ntpsapi::{
		PEB_LDR_DATA, 
		THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
		THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH
	},
	ntpebteb::{
		API_SET_NAMESPACE,
		API_SET_NAMESPACE_ENTRY,
		API_SET_VALUE_ENTRY,
	},
	ntioapi::{
		IO_STATUS_BLOCK, 
		FILE_NON_DIRECTORY_FILE, 
		FILE_STANDARD_INFORMATION, 
		FILE_SYNCHRONOUS_IO_NONALERT, 
		FileStandardInformation, 
	},
};

use winapi::{
	um::winnt::*,
	shared::{
		minwindef::MAX_PATH,
		ntdef::{
			OBJECT_ATTRIBUTES64,
			OBJECT_ATTRIBUTES,
			UNICODE_STRING64,
			UNICODE_STRING,
			RTL_BALANCED_NODE,
			LIST_ENTRY,
		},
	}

};

use interface::*;
use nt_syscall::*;
use aligned::*;
mod tools;
use tools::*;


















/*
#[no_mangle]
pub unsafe extern "system" fn loader(image_base: usize) -> usize {
	else if root.operation == Ops::Cleanup {
		if root.depth == 0 {
			// Unallocate file buffer if it's not needed antmore
			if root.file_buffer != 0 {
				// Free file buffer
				// Windows says size should be zero when releasing
				let region_size = 0;
				syscall!(
					root.virtual_free, // NtFeeVirtualMemory
					CURRENT_PROCESS, // ProcessHandle
					&root.file_buffer as *const _, // BaseAddress
					&region_size as *const _, // RegionSize
					MEM_RELEASE // FreeType
				);
			}
		}

		// Wipe header (the state and primary loader data has must be wiped from the dll)
		if root.depth != 0 {
			// Wipe sections
			let sections: *mut SectionInfo = base.cast::<LoaderData>().offset(1).cast();
			for index in 0..data.section_count{
				sections.offset(index as isize).write(zeroed());
			}
			// Wipe loader data
			*data = zeroed();
		}


		// Wipe import directory
		//			if data.
		// Wipe tls, delay import, reloc, debug, 


		// Set headers to readonly
		syscall!(
			root.virtual_protect, // NtProtectVirtualMemory
			CURRENT_PROCESS,  // ProcessHandle
			&image_base as *const _, // BaseAddress
			&data.size as *const _, // RegionSize
			PAGE_NOACCESS, // NewProtect
			&unused as *const _ // OldProtect
		);
		return 0;
	}



	// Invalid operation
	return 0;
}
*/




// TODO: cleanup/stripping, delay load, bound import




#[no_mangle]
#[cfg(target_arch = "x86_64")]
pub unsafe extern "system" fn heavens_gate(state_base: usize) {
	if state_base == 0 {
		return;
	}
	let state: &mut State = transmute(state_base);
	let entry_pointer: EntryX86 = callable!(state_base, state.entry);


	// TODO: this dies because the stack popinter points to unallocated memory.
	// I should create/hijack a thread and then set its meta info or whatev to a stack loacted < u32::max

	// I should also be careful about walking the peb since i shouldn't find the wrong dll

	asm!(
		"",

		in("rax") entry_pointer,
		in("rcx") state_base,
		lateout("rax") _,
		lateout("rcx") _,
	);
	enter_x86!();
	asm!(
		// push ecx
		".byte 0x51",
		// cal eax
		".byte 0xff", ".byte 0xd0",

		//lateout("rax") _, lateout("rcx") _, out("rdx") _, out("rsi") _,
		//out("r8") _, out("r9") _, out("r10") _, out("r11") _,
		//out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
		//out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
		//out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
		//out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
	);
	enter_x64!();
}
#[no_mangle]
#[cfg(target_arch = "x86")]
pub unsafe extern "system" fn heavens_gate(state_base: usize) {
	if state_base == 0 {
		return;
	}
	let state: &mut State = transmute(state_base);

	//write_debug!(state, Call = HeavensGate(1));
	//write_debug!(state, Value = state_base);


	let entry_pointer: EntryX64 = callable!(state_base, state.entry);
	let stack_pointer: u32;


	asm!(
		"mov eax, esp",
		out("eax") stack_pointer,
	);
	enter_x64!();
	asm!(
		".byte 0x48", "and esp, 0xfffffff0",
		".byte 0x48", "xor eax, eax",
		".byte 0x48", "xor ecx, ecx",
		".byte 0x48", "xor edi, edi",
		
		out("eax") _,
		out("ecx") _,
		out("edi") _,
	);
	asm!(
		"sub esp, 0x30",
		"push edi",
		"call eax",
		"pop esp",

		in("eax") entry_pointer,
		in("ecx") state_base,
		in("edi") stack_pointer,

		lateout("eax") _, lateout("ecx") _, lateout("edi") _, 
		out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
		out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
	);
	enter_x86!();
}


/*
	entry point for newly mapped image
*/
#[no_mangle]
pub unsafe extern "system" fn entry(state_base: usize) {	
	if state_base == 0 {
		return;
	}
	let state: &mut State = transmute(state_base);
	state.base = state_base as u64;

	write_debug!(state, Call = Entry(1));
	write_debug!(state, Value = state_base);


	// Release hijacked thread by spawning a new one
	if flag!(state.options, Options::ReleaseThread) {
		// TODO push guard
		//asm!("push rax");
		state.options = flag!(state.options, Options::ReleaseThread, false) as u32;
		let create_flags = if flag!(state.options, Options::HideThread) {
			THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH
		} else {
			0
		};
		
		let mut unused: u64 = 0 as _;
		syscall!(
			state.syscall_create_thread, // NtCreateThreadEx
			&mut unused as *mut _, // ThreadHandle
			STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL, // DesiredAccess
			0, //ObjectAttributes
			CURRENT_PROCESS, // ProcessHandle
			state.base + state.entry as u64, // StartRoutine
			state_base, // Argument
			create_flags, // CreateFlags
			0, // ZeroBits
			0, // StackSize
			0, // MaximumStackSize
			0 // AttributeList
		);
		
		// release thread

		// TODO pop guard
		//asm!("pop rax");
		return;
	}



	let find_module_pointer: FindModule = callable!(state.base, state.find_module);
	let resolve_function_pointer: ResolveFunction = callable!(state.base, state.resolve_function);
	let parse_header_pointer: ParseHeader = callable!(state.base, state.parse_header);




	// Parse the module
	let image_base = state.image as usize;
	if image_base == 0 {
		// No image to patch
		write_debug!(state, Failure = NoImage);
		return;
	}
	
	let (nt, sections) = match parse_header_pointer(state, image_base) {
		Some((address, sections)) => (
			transmute::<_, &IMAGE_NT_HEADERS>(address),
			transmute::<_, *const IMAGE_SECTION_HEADER>(sections),
		),
		None => {
			write_debug!(state, Failure = InvalidBuffer);
			return;
		}
	};


	let do_relocations = {
		flag!(nt.OptionalHeader.DllCharacteristics, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) &&
		nt.OptionalHeader.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_BASERELOC as u32
	};
	let do_resolve_imports = nt.OptionalHeader.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_IMPORT as u32;
	let do_initialize_cookie = {
		flag!(state.options, Options::InitializeCookie) &&
		nt.OptionalHeader.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG as u32
	};
	let do_execute_main = {
		flag!(nt.FileHeader.Characteristics, IMAGE_FILE_EXECUTABLE_IMAGE) &&
		nt.OptionalHeader.AddressOfEntryPoint != 0
	};
	let do_execute_tls = {
		flag!(nt.FileHeader.Characteristics, IMAGE_FILE_EXECUTABLE_IMAGE) &&
		nt.OptionalHeader.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_TLS as u32
	};




	// Do relocations
	if do_relocations {
		let delta = image_base as i64 - nt.OptionalHeader.ImageBase as i64;
		let offset = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize;
		if delta != 0 && offset != 0 {
			write_debug!(state, Info = Relocating);

			// Enumerate all relocation blocks
			// The last one is zeroed 
			// TODO: use a root pointer and then offset by number of blocks instead of doing it liek thsi
			let mut block: &IMAGE_BASE_RELOCATION = transmute(image_base + offset);
			while block.VirtualAddress != 0 {
				let count = (block.SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>();
				let relocations = (block as *const IMAGE_BASE_RELOCATION).offset(1).cast::<u16>();

				// Enumerate all relocations within the block
				for index in 0..count {
					let value = relocations.offset(index as isize).read();
					let based = value >> 0xc;
					let offset = value & 0xfff;
					let pointer = (image_base + block.VirtualAddress as usize + offset as usize) as *mut u8;

					// Relocate based on relocation type
					// A normal if/match gets compiled to a jump table, so some fucklery is needed to avoid that
					// The values are random to avoid being normalized
					const BASED_DIR64: u64 = 0x24;
					const BASED_HIGHLOW: u64 = 0x9473;
					const BASED_HIGHADJ: u64 = 0x227849334813;
					const BASED_HIGH: u64 = 0x73845854;
					let actual = {
						(based == IMAGE_REL_BASED_DIR64) as u64 * BASED_DIR64 +
						(based == IMAGE_REL_BASED_HIGHLOW) as u64 * BASED_HIGHLOW +
						(based == IMAGE_REL_BASED_HIGHADJ) as u64 * BASED_HIGHADJ +
						(based == IMAGE_REL_BASED_HIGH) as u64 * BASED_HIGH
					};
					if actual == BASED_DIR64 {
						// Destination as i64 += delta as i64
						let pointer = pointer.cast::<i64>();
						pointer.write(pointer.read() + delta as i64);
					}
					else if actual == BASED_HIGHLOW {
						// Destination as i32 += delta as i32
						let pointer = pointer.cast::<i32>();
						pointer.write(pointer.read() + (delta & 0xffffffff) as i32);
					}	
					else if actual == BASED_HIGHADJ {
						// Destination as i32 high += delta as i32 high
						// Destination as i32 low += delta as i32 low
						let mut pointer = pointer.cast::<i16>();
						pointer.write(pointer.read() + ((delta >> 0x10) & 0xffff) as i16);
						pointer = pointer.offset(1);
						pointer.write(pointer.read() + (delta & 0xffff) as i16);
					}
					else if actual == BASED_HIGH {
						// Destination as i16 += delta as i32 high
						let pointer = pointer.cast::<i16>();
						pointer.write(pointer.read() + ((delta >> 0x10) & 0xffff) as i16);
					}
				}

				// Go to the next block, that is located right after the current one
				block = transmute(block as *const _ as usize + block.SizeOfBlock as usize);
			}
		} else {
			// TODO: log this
		}
	}




	// Reslove imports
	if do_resolve_imports {
		let offset = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize;
		if offset != 0 {
			write_debug!(state, Info = ResolvingImports);

			// Enumerate descriptors and resolve them, last one is zeroed
			let mut descriptor: &IMAGE_IMPORT_DESCRIPTOR = transmute(image_base + offset);
			while descriptor.Name != 0 {
				let mut address_table: &mut IMAGE_THUNK_DATA  = transmute(image_base + descriptor.FirstThunk as usize);
				let mut name_table: &mut IMAGE_THUNK_DATA = if *descriptor.u.OriginalFirstThunk() != 0 {
					// Use the original thunk
					transmute(image_base + *descriptor.u.OriginalFirstThunk() as usize)
				} else {
					// Import binding was not used, use the first thunk instead.
					transmute(image_base + descriptor.FirstThunk as usize)
				};


				let module_name = (image_base + descriptor.Name as usize) as *const u8;
				let module_name_length = string_len!(StringU8 = module_name, Token[0, '.']);
				let module = match find_module_pointer(state, CString::U8(module_name), module_name_length) {
					Some(module) => module,
					None => {
						// Module not found, continue to next descriptor
						descriptor = transmute((descriptor as *const IMAGE_IMPORT_DESCRIPTOR).offset(1));
						continue;
					}
				};

				// Parse headers
				let entry = match parse_header_pointer(state, module) {
					Some((address, _)) => (
						transmute::<_, &IMAGE_NT_HEADERS>(address).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
					),
					None => {
						descriptor = transmute((descriptor as *const IMAGE_IMPORT_DESCRIPTOR).offset(1));
						continue;
					}
				};
				let export_rva = entry.VirtualAddress as usize;
				let export_size = entry.Size as usize;


				// Enumerate import thunks, last is zeroed
				while *name_table.u1.AddressOfData() != 0 {
					let address;

					// Import by name
					let ordinal = *name_table.u1.Ordinal() as usize;
					let mut hint = None;
					let mut name = None;
					if !flag!(ordinal, IMAGE_ORDINAL_FLAG as usize) {
						let import: &IMAGE_IMPORT_BY_NAME = transmute(image_base + *name_table.u1.AddressOfData() as usize);
						hint = Some(import.Hint as u32);
						name = Some(CString::U8(transmute(&import.Name)));
					};
					
					address = resolve_function_pointer(state, module, export_rva, export_size, Some(ordinal), name, hint);

					/*if flag!(ordinal, IMAGE_ORDINAL_FLAG as usize) {
						// Import by ordinal
						address = resolve_function_pointer(state, module, export_rva, export_size, Some(ordinal), None, None)
							.unwrap_or(0);
					} else {
						// Import by name
						let (hint, name) = {
							let import: &IMAGE_IMPORT_BY_NAME = transmute(image_base + *name_table.u1.AddressOfData() as usize);
							(import.Hint as u32, &import.Name as *const i8 as *const u8)
						};
						address = resolve_function_pointer(state, module, export_rva, export_size, Some(ordinal), Some(CString::U8(name)), Some(hint))
							.unwrap_or(0);
					}
					*/

					// Write the function pointer into the import address table
					*address_table.u1.Function_mut() = if let Some(address) = address {
						address as _
					} else {
						0xffff_ffff_ff_badd11_u64 as usize as _
					};

					// Go to the next set of thunks
					address_table = transmute((address_table as *const IMAGE_THUNK_DATA).offset(1));
					name_table = transmute((name_table as *const IMAGE_THUNK_DATA).offset(1));
				}

				// Go to the next import descriptor
				descriptor = transmute((descriptor as *const IMAGE_IMPORT_DESCRIPTOR).offset(1));
			}
		} else {
			// TODO: log this
		}
	}

/*
	// Reslove delayed imports
	if nt.OptionalHeader.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT as u32 && false {
		let offset = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT as usize].VirtualAddress as usize;
		if offset != 0 {
			// Enumerate descriptors and resolve them, last one is zeroed
			let mut descriptor: &IMAGE_DELAYLOAD_DESCRIPTOR = transmute(image_base + offset);
			while descriptor.DllNameRVA != 0 {
				let mut address_table: &mut IMAGE_THUNK_DATA  = transmute(image_base + descriptor.ImportAddressTableRVA as usize);
				let mut name_table: &mut IMAGE_THUNK_DATA = transmute(image_base + descriptor.ImportNameTableRVA as usize);


				let module_name = (image_base + descriptor.DllNameRVA as usize) as *const u8;
				let module = match find_module_pointer(state, CString::U8(module_name)) {
					Some(module) => module,
					None => {
						// Module not found, continue to next descriptor
						descriptor = transmute((descriptor as *const IMAGE_DELAYLOAD_DESCRIPTOR).offset(1));
						continue;
					}
				};


				if descriptor.ModuleHandleRVA != 0 {
					((image_base + descriptor.ModuleHandleRVA as usize) as *mut usize).write(module);				
				}


				// Enumerate import thunks, last is zeroed
				while *name_table.u1.AddressOfData() != 0  && false{
					let address;

					let ordinal = *name_table.u1.Ordinal() as usize;
					if flag!(ordinal, IMAGE_ORDINAL_FLAG as usize) {
						// Import by ordinal
						address = resolve_function_pointer(state, module, Some(ordinal), None, None).unwrap_or(0);
					} else {
						// Import by name
						let (hint, name) = {
							let import: &IMAGE_IMPORT_BY_NAME = transmute(image_base + *name_table.u1.AddressOfData() as usize);
							(import.Hint as u32, &import.Name as *const i8 as *const u8)
						};
						address = resolve_function_pointer(state, module, Some(ordinal), Some(CString::U8(name)), Some(hint)).unwrap_or(0);
					}

					// Write the function pointer into the import address table
					*address_table.u1.Function_mut() = if address != 0 {
						address as _
					} else {
						0xffff_ffff_ff_badd11_u64 as usize as _
					};

					// Go to the next set of thunks
					address_table = transmute((address_table as *const IMAGE_THUNK_DATA).offset(1));
					name_table = transmute((name_table as *const IMAGE_THUNK_DATA).offset(1));
				}

				// Go to the next import descriptor
				descriptor = transmute((descriptor as *const IMAGE_DELAYLOAD_DESCRIPTOR).offset(1));
			}
		}
	}*/






	// Generate security cookie
	if do_initialize_cookie {
		let offset = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG as usize].VirtualAddress as usize;
		if offset != 0 {
			let directory: &mut IMAGE_LOAD_CONFIG_DIRECTORY = transmute(image_base + offset);

			// Generate some pseudo random shiz
			let mut cookie: u64 = image_base as u64;
			cookie ^= teb!().ClientId.UniqueProcess as u64;
			cookie ^= teb!().ClientId.UniqueThread as u64;
			cookie ^= timestamp!() as u64;
			//cookie ^= rdrand!() as u64;

			#[cfg(target_arch = "x86")] {
				cookie &= 0xffffffff;
				if cookie == 0xbb40e64e {
					cookie = 0xbb40e64f;
				}
				else if (cookie & 0xffff0000) == 0 {
					cookie |= (cookie | 0x4711) << 0x10;
				}
			}
			#[cfg(target_arch = "x86_64")] {
				cookie &= 0x0000ffffffffffff;
				if cookie == 0x2b992ddfa232 {
					cookie += 1;
				} 
				else if (cookie & 0x0000ffff00000000) == 0 {
					cookie |= (cookie | 0x4711) << 0x10;
				}
			}

			// Write the cookie
			// TODO: this dont event work lol, infact it crashes
			// SEcutiry cookie might be relative to something =???????????????

			// I might have to rebase cookie?? but i though relocation took care of that
			//directory.SecurityCookie = cookie as _;
		}
	}



	// TODO: protect headers


	// Apply correct protection to each section
	for index in 0..nt.FileHeader.NumberOfSections {
		let section: &IMAGE_SECTION_HEADER =  transmute(sections.offset(index as isize));
		let size = *section.Misc.VirtualSize() as u64;
		let address = image_base as u64 + section.VirtualAddress as u64;

		// Discard any section that are not needed
		let discardable = flag!(section.Characteristics , IMAGE_SCN_MEM_DISCARDABLE);
		if discardable {
			// TODO: wipe data
		}


		// Parse page protection from section characteristics
		let protection: u32;
		let execute = flag!(section.Characteristics , IMAGE_SCN_MEM_EXECUTE);
		let read = flag!(section.Characteristics , IMAGE_SCN_MEM_READ);
		let write = flag!(section.Characteristics , IMAGE_SCN_MEM_WRITE);
		if execute && read && write {
			protection = PAGE_EXECUTE_READWRITE;
		}
		else if execute && read {
			protection = PAGE_EXECUTE_READ;
		}
		else if read && write {
			protection = PAGE_READWRITE;
		}
		else if execute {
			protection = PAGE_EXECUTE;
		}
		else if read {
			protection = PAGE_READONLY;
		} else {
			protection = PAGE_NOACCESS;
		}


		// Apply the protection
		let unused: u64 = 0;
		syscall!(
			state.syscall_virtual_protect, // NtProtectVirtualMemory
			CURRENT_PROCESS,  // ProcessHandle
			&address as *const _, // BaseAddress
			&size as *const _, // RegionSize
			protection, // NewProtect
			&unused as *const _ // OldProtect
		);
	}






	// TODO: cleanup and wiping



	// Execute tls callbacks
	if do_execute_tls {
		// Handle thread local storage data and callbacks
		let offset = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize].VirtualAddress as usize;
		if offset != 0 {
			let directory: &IMAGE_TLS_DIRECTORY = transmute(image_base + offset);

			// TODO: allocate memory ??

			// Execute callbacks
			let mut callback: *const usize = transmute(directory.AddressOfCallBacks);
			while callback.read() != 0 {
				let address = callback.read();

				write_debug!(state, Call = TlsCallback);

				let tls_callback: TlsCallback = transmute(address);
				tls_callback(image_base as _, DLL_PROCESS_ATTACH, 0 as _);
				callback = callback.offset(1);

				write_debug!(state, Success = 0);
			}
		}
	}

	// Execute dll main
	if do_execute_main {
		let address = image_base + nt.OptionalHeader.AddressOfEntryPoint as usize;

		write_debug!(state, Call = DllMain);

		// Call dllmain and for main image (non dependency) pass loader base
		// for deallocation or loader cache referencing or something
		let dll_main: DllMain = transmute(address);
		let reserved = if state.depth == 0 {
			state_base
		} else {
			0
		};
		asm!("nop");
		asm!("nop");
		asm!("nop");
		let status = dll_main(state.image as _, DLL_PROCESS_ATTACH, reserved as _);
		asm!("nop");
		asm!("nop");
		asm!("nop");

		write_debug!(state, Success = 1);
		write_debug!(state, Value = status);
	}


	write_debug!(state, Success = 0);
	write_debug!(state, Info = MappingSuccessful);
}




#[no_mangle]
pub unsafe fn parse_header(state: &mut State, module: usize) -> Option<(usize, usize)> {
	write_debug!(state, Call = ParseHeader(1));
	write_debug!(state, Value = module);




	if module == 0 {
		write_debug!(state, Failure = InvalidModule);
		return None;
	}

	let dos: &IMAGE_DOS_HEADER = transmute(module);
	if dos.e_magic != IMAGE_DOS_SIGNATURE {
		write_debug!(state, Failure = InvalidDosHeader);
		return None;
	}

	let nt: &IMAGE_NT_HEADERS = transmute(module + dos.e_lfanew as usize);
	if nt.Signature != IMAGE_NT_SIGNATURE {
		write_debug!(state, Failure = InvalidNtHeader);
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
		write_debug!(state, Failure = InvalidMagic(nt.OptionalHeader.Magic));
		return None;
	}
	if !machine {
		write_debug!(state, Failure = InvalidMachine(nt.FileHeader.Machine));
		return None;
	}

	let address = transmute::<_, usize>(nt);
	let sections = module + dos.e_lfanew as usize + size_of::<u32>() + size_of::<IMAGE_FILE_HEADER>() + nt.FileHeader.SizeOfOptionalHeader as usize;

	write_debug!(state, Success = 2);
	write_debug!(state, Value = address);
	write_debug!(state, Value = sections);
	Some((address, sections))
}




/*
	Search order:
		memory:
			loader cache,
			peb apisets (if applicable),
			peb ldr,
		disk: (see load_module)

	Note: 
		The module name does not end in .dll
*/
#[no_mangle]
pub unsafe fn find_module(state: &mut State, name: CString, mut name_length: usize) -> Option<usize> {
	write_debug!(state, Call = FindModule(2));
	write_debug!(state, String = name, Length = name_length, Token[0, '.']);
	write_debug!(state, Value = name_length);




	let find_module_pointer: FindModule = callable!(state.base, state.find_module);
	let load_module_pointer: LoadModule = callable!(state.base, state.load_module);




	// Check if it's an apiset
	let mut is_api = false;
	if name_length >= PREFIX_LENGTH {
		let prefix_hash = hash!(String = name, true, Length = PREFIX_LENGTH, Token[0]);
		if prefix_hash == API_PREFIX_HASH || prefix_hash == EXT_PREFIX_HASH {
			write_debug!(state, Info = ImageIsApi);	
			is_api = true;
			// Ignore '-x' postfix in apiset
			name_length -= 2;
		}
	}




	// If it's been loaded by us, it'll be hidden, so do a lookup in the loader cache
	let hash = hash!(String = name, true, Length = name_length, Token[0]);
	let cache = (state as *mut State).offset(1).cast::<CacheEntry>();
	for index in 0..state.cache_length {
		let entry: &CacheEntry = transmute(cache.offset(index as isize));
		if hash == entry.hash {
			write_debug!(state, Info = ImageFoundInCache);
			write_debug!(state, Success = 1);
			write_debug!(state, Value = entry.module);
			return Some(entry.module  as usize);
		}
	}




	// If's it's an apiset then resolve it's host
	if is_api {
		let apiset_base: *const u8 = peb!().ApiSetMap as *const u8;
		let apiset: &API_SET_NAMESPACE = transmute(apiset_base);
	
		let entries: *const API_SET_NAMESPACE_ENTRY = apiset_base.offset(apiset.EntryOffset as isize).cast();
		for index in 0..apiset.Count {
			let entry: &API_SET_NAMESPACE_ENTRY = transmute(entries.offset(index as isize));
			let api_length = entry.NameLength / size_of::<u16>() as u32 - 2;
			let api_name = apiset_base.offset(entry.NameOffset as isize).cast::<u16>();

			if api_length == name_length as u32 && name_length >= 2 {
				let value_entries: *const API_SET_VALUE_ENTRY = apiset_base.offset(entry.ValueOffset as isize).cast();
				let value_entry: &API_SET_VALUE_ENTRY = transmute(value_entries.offset(entry.ValueCount as isize - 1));
				let host_length = value_entry.ValueLength / size_of::<u16>() as u32;
				let host_name = apiset_base.offset(value_entry.ValueOffset as isize).cast::<u16>();
	
				let status = string_cmp!(String = name, String = CString::U16(api_name), true, Length = api_length, Token[0]);
				let is_equal = status == Strcmp::Equal || status == Strcmp::LeftLonger || status == Strcmp::RightLonger; 
				if is_equal && host_length >= 4 {
					// Matching apiset found
					// Resolve host module
					if let Some(module) = find_module_pointer(state, CString::U16(host_name), host_length as usize - 4 /* TODO: fix this , it's toi offset the .dll ext*/) {
						// Module resolved
						// Insert into our cache
						let cache = (state as *mut State).offset(1).cast::<CacheEntry>();
						if state.cache_length + 1 < state.cache_max_length {
							cache.offset(state.cache_length as isize).write(CacheEntry {
								hash: hash as _,
								module: module as _,
							});
							state.cache_length += 1;
						} else {
							write_debug!(state, Failure = CacheLimitReached);
							return None;
						}
						
						write_debug!(state, Info = ImageFoundInApi);
						write_debug!(state, Success = 1);
						write_debug!(state, Value = module);
						return Some(module);
					}
				}
			}
		}
	}




	// Walk the peb's ldr chain and try to find the dll if it's already loaded
	let ldr_data = transmute::<_, &mut PEB_LDR_DATA>(peb!().Ldr);
	let head = (&mut ldr_data.InMemoryOrderModuleList) as *mut LIST_ENTRY;
	let mut flink = head;
	loop {
		let entry = transmute::<_, &mut LDR_DATA_TABLE_ENTRY>(flink.offset(-1));
		let entry_name = CString::U16(entry.BaseDllName.Buffer);
		let entry_length = entry.BaseDllName.Length;

		if !entry_name.is_null() && entry_length > 0 {
			let status = string_cmp!(String = name, String = entry_name, true, Length = entry_length, Token[0, '.']);
			if status == Strcmp::Equal {
				let module = entry.DllBase;
	
				write_debug!(state, Info = ImageFoundInPeb);
				write_debug!(state, Success = 1);
				write_debug!(state, Value = module);
				return Some(module as usize);
			}
		}


		flink = flink.read().Flink;
		if flink == head {
			break;
		}
	};


	

	// Module not found in memory
	// Try to load it from disk instead
	if let Some(module) = load_module_pointer(state, name, name_length) {
		write_debug!(state, Info = ImageFoundInDisk);
		write_debug!(state, Success = 1);
		write_debug!(state, Value = module);
		return Some(module);
	}


	// Image not found
	write_debug!(state, Failure = NotFound);
	None
}




/**
	Tries loading a module from disk
	Search order:
		disk:
			system32 (x64),
			syswow64 (x86),
			path environment variable,

	parameters:
		state: reference to shared state
		name: pointer to module name

	return:
		Success -> Some(module address)
		Failure -> None
*/
// TODO: Try current directory too
#[no_mangle]
pub unsafe fn load_module(state: &mut State, name: CString, name_length: usize) -> Option<usize> {
	write_debug!(state, Call = LoadModule(2));
	write_debug!(state, String = name, Length = name_length, Token[0, '.']);
	write_debug!(state, Value = name_length);
	



	let map_module_pointer: MapModule = callable!(state.base, state.map_module);
	let read_file_pointer: ReadFile = callable!(state.base, state.read_file);




	// Buffer (on stack) to hold file path
	let path_buffer: MaybeUninit<[u16; FILEPATH_BUFFER_SIZE]> = MaybeUninit::uninit();
	let mut buffer: *mut u16 = transmute(&path_buffer);

	// Prepend the file path with "\??\" because windows says so
	// and offset the buffer to point infront of the prefix
	buffer.cast::<u64>().write(STRING_PREFIX);
	buffer = buffer.offset(STRING_SEGMENT_LENGTH);




	// Repeated code
	macro_rules! try_load_module {
		( $length:expr, $where:ident ) => {{
			let mut length = $length;
			write_debug!(state, Value = length);

			// Append the name of the dll and '.dll' to the file path to make a complete file path
			length += memcpy!(String = CString::U16(buffer.offset(length)), String = name, Length = name_length, Token[0, '.']) as isize;
			write_debug!(state, Value = length);
	
			buffer.offset(length).cast::<u64>().write(STRING_DLL);
			length += STRING_SEGMENT_LENGTH * 2;
			write_debug!(state, Value = length);
	
			// Try to read the file using the complete file path
			let dos_path: *const u16 = transmute(&path_buffer);
			let name_length = name_length + STRING_SEGMENT_LENGTH as usize;
			let name = dos_path.offset(length - name_length as isize);
			let path_length = length - STRING_SEGMENT_LENGTH;
			let path = dos_path.offset(STRING_SEGMENT_LENGTH);
			if let Some(_) = read_file_pointer(state, dos_path, length as usize) {
				if let Some(module) = map_module_pointer(state, CString::U16(name), name_length, CString::U16(path), path_length as usize) {
					// Image has been found, read and mapped
					write_debug!(state, Info = $where);
					write_debug!(state, Success = 1);
					write_debug!(state, Value = module);
					return Some(module);
				} else {
					// File found but not what we're looking for
				}
			} else {
				// File not found
			}
		}}
	}
	#[cfg(target_arch = "x86_64")]
	macro_rules! write_root {
		( $( $from:expr )* ) => {{
			// Append '/system32/' to the buffer
			let length = memcpy!(String = CString::U16(buffer), String = $( $from )*, Length = MAX_PATH, Token[0, ';']) as isize;
			buffer.offset(length + STRING_SEGMENT_LENGTH * 0).cast::<u64>().write(STRING_SYSTEM32[0]);
			buffer.offset(length + STRING_SEGMENT_LENGTH * 1).cast::<u64>().write(STRING_SYSTEM32[1]);
			buffer.offset(length + STRING_SEGMENT_LENGTH * 2).cast::<u64>().write(STRING_SYSTEM32[2]);
			length + STRING_SYSTEM32_LENGTH
		}}
	}
	#[cfg(target_arch = "x86")]
	macro_rules! write_root {
		( $( $from:expr )* ) => {{
			// Append '/syswow64/' to the buffer
			let length = memcpy!(String = CString::U16(buffer), String = $( $from )*, Length = MAX_PATH, Token[0, ';']) as isize;
			buffer.offset(length + STRING_SEGMENT_LENGTH * 0).cast::<u64>().write(STRING_SYSWOW64[0]);
			buffer.offset(length + STRING_SEGMENT_LENGTH * 1).cast::<u64>().write(STRING_SYSWOW64[1]);
			buffer.offset(length + STRING_SEGMENT_LENGTH * 2).cast::<u64>().write(STRING_SYSWOW64[2]);
			length + STRING_SYSWOW64_LENGTH
		}}
	}




	// Do a fast lookup
	let kuser = transmute::<_, &mut KUSER_SHARED_DATA>(KUSER_ADDRESS as usize);
	let system_root = &kuser.NtSystemRoot as *const u16; 
	if !system_root.is_null() {
		try_load_module!(write_root!(CString::U16(system_root)), ImageFoundInSystemRoot);
	}

	// Not found, time to get our hands dirty ...


	// Walk through environment variables and try to find paths
	let (mut environment_path, system_root, windir) = {
		let mut environment_path = 0 as *const u16;
		let mut system_root = 0 as *const u16;
		let mut windir = 0 as *const u16;

		let process_params = transmute::<_, &mut RTL_USER_PROCESS_PARAMETERS>(peb!().ProcessParameters);
		let mut pointer = process_params.Environment as *const u16;
		let size= process_params.EnvironmentSize;
		

		// Environment has the following format:
		// name = body NULL
		// name = body NULL
		// ...
		// NULL
		let mut count = 0; 
		while pointer.read() != 0 && count < size {
			// Compare the name of the variable to those we're looking for
			let length = string_len!(StringU16 = pointer, Token[0, '=']) + 1;
			let hash = hash!(StringU16 = pointer, true, Length = length, Token[0]);
			if length == ENVIRONMENT_PATH_LENGTH && hash == ENVIRONMENT_PATH_HASH {
				environment_path = pointer.offset(length as isize);
			}
			if length == ENVIRONMENT_SYSTEMROOT_LENGTH && hash == ENVIRONMENT_SYSTEMROOT_HASH{
				system_root = pointer.offset(length as isize);
			}
			if length == ENVIRONMENT_WINDIR_LENGTH && hash == ENVIRONMENT_WINDIR_HASH {
				windir = pointer.offset(length as isize);
			}

			if !environment_path.is_null() && !system_root.is_null() && !windir.is_null() {
				// Found what we're looking for, no need to continue
				break;
			}

			// Skip over the body of the variable
			while pointer.read() != 0 && count < size  {
				pointer = pointer.offset(1);
				count += 1;
			}
			
			pointer = pointer.offset(1);
			count += 1;
		}
		(environment_path, system_root, windir)
	};


	// Try %systemroot%/( system32 | syswow64 )/*
	if !system_root.is_null() {
		try_load_module!(write_root!(CString::U16(system_root)), ImageFoundInSystemRoot);
	}
	write_debug!(state, Info = ImageNotInSystemRoot);

	// Try %windir%/( system32 | syswow64 )/*
	if !windir.is_null() {
		try_load_module!(write_root!(CString::U16(windir)), ImageFoundInWindir);
	}
	write_debug!(state, Info = ImageNotInWindir);


	// Try path
	// Path has the following format:
	// name = body ;
	// name = body ;
	// ...
	// NULL
	if !environment_path.is_null() {
		let mut length: isize;
		while environment_path.read() != 0 {
			// append file path
			length = memcpy!(StringU16 = buffer, StringU16 = environment_path, Length = FILEPATH_BUFFER_SIZE, Token[0, ';']) as isize;
	
			if environment_path.offset(length).read() == 0 {
				// Reached the end of path
				break;
			}
			if length == 0 {
				// Invalid path
				environment_path = environment_path.offset(1);
				continue;
			}
			environment_path = environment_path.offset(length + 1);
			
	
			// Make sure the file path ends in a trailing slash, hacky but it works
			if buffer.offset(length).read() == '\\' as u16 {
				length += 1;
			}
			if buffer.offset(length - 1).read() != '\\' as u16 {
				if buffer.offset(length).read() != '\\' as u16 {
					buffer.offset(length).write('\\' as u16);
					length += 1;
				}
			}
	
			try_load_module!(length, ImageFoundInEnvironmentPath);
		}
	}
	write_debug!(state, Info = ImageNotInEnvironmentPath);

	
	// Image has not been found on disk
	write_debug!(state, Failure = NotFound);
	None
}




#[no_mangle]
pub unsafe fn map_module(state: &mut State, name: CString, name_length: usize, path: CString, path_length: usize) -> Option<usize> {
	write_debug!(state, Call = MapModule(4));
	write_debug!(state, String = name, Length = name_length, Token[0]);
	write_debug!(state, Value = name_length);
	write_debug!(state, String = path, Length = path_length, Token[0]);
	write_debug!(state, Value = path_length);




	let parse_header_pointer: ParseHeader = callable!(state.base, state.parse_header);
	let link_module_pointer: LinkModule = callable!(state.base, state.link_module); 
	let entry_pointer: Entry = callable!(state.base, state.entry);



	
	let file_base = match state.file_buffer {
		Some(bufer) => bufer as usize,
		None => {
			// Buffer is not allocated
			write_debug!(state, Failure = InvalidBuffer);
			return None;
		}
	};
	if let Some(size) = state.file_buffer_size {
		if (size as usize) < size_of::<IMAGE_DOS_HEADER>() + size_of::<IMAGE_NT_HEADERS>() {
			// Buffer is not large enough for the headers
			write_debug!(state, Failure = BufferTooSmall);
			return None;
		}
	} else {
		// Buffer is not allocated
		write_debug!(state, Failure = InvalidBuffer);
		return None;
	}
	

	// Parse image
	let (nt, sections) = match parse_header_pointer(state, file_base) {
		Some((address, sections)) => (
			transmute::<_, &IMAGE_NT_HEADERS>(address),
			transmute::<_, *const IMAGE_SECTION_HEADER>(sections)
		),
		None => {
			// Failed to parse headers
			write_debug!(state, Failure = InvalidHeader);
			return None;
		}
	};

	
	let mut module = nt.OptionalHeader.ImageBase as u64;
	let image_size = nt.OptionalHeader.SizeOfImage as u64;
	let header_size = nt.OptionalHeader.SizeOfHeaders as u64;
	let section_count = nt.FileHeader.NumberOfSections;

	
	// Map image
	if flag!(nt.OptionalHeader.DllCharacteristics, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		// Image can be relocated so just allocate at a random address
		write_debug!(state, Info = ImageIsDynamicBase);

		module = 0;
		let status = syscall!(
			state.syscall_virtual_allocate, // NtAllocateVirtualMemory
			CURRENT_PROCESS, // ProcessHandle
			&module as *const _, // BaseAddress
			0, // ZeroBits
			&image_size as *const _, // RegionSize
			MEM_COMMIT | MEM_RESERVE, // AllocationType
			PAGE_READWRITE // Protect
		);
		if !ntstatus_valid!(status) || module == 0 {
			// Failed to allocate buffer
			write_debug!(state, Failure = FailedToAllocateBuffer(status));
			return None;
		}
	} else {
		// Image cannot be relocated so try to allocate at image base
		let status = syscall!(
			state.syscall_virtual_allocate, // NtAllocateVirtualMemory
			CURRENT_PROCESS, // ProcessHandle
			&module as *const _, // BaseAddress
			0, // ZeroBits
			&image_size as *const _, // RegionSize
			MEM_COMMIT | MEM_RESERVE, // AllocationType
			PAGE_READWRITE // Protect
		);
		if !ntstatus_valid!(status) || module == 0 {
			// Failed to allocate buffer
			write_debug!(state, Failure = FailedToAllocateBuffer(status));
			return None;
		}
	}


	// Write image header into module
	memcpy!(StringU8 = module, StringU8 = file_base, Length = header_size);

	// Write image sections into module
	for index in 0..section_count as isize {
		let section: &IMAGE_SECTION_HEADER = transmute(sections.offset(index));
		
		write_debug!(state, StringU8 = &section.Name, Length = section.Name.len());

		// Don't write section if it's not used
		let no_access = {
			!flag!(section.Characteristics, IMAGE_SCN_MEM_EXECUTE) &&
			!flag!(section.Characteristics, IMAGE_SCN_MEM_READ) &&
			!flag!(section.Characteristics, IMAGE_SCN_MEM_WRITE)
		};
		if no_access {
			continue;
		}

		// Get size of section
		let mut raw_size = section.SizeOfRawData;
		if raw_size == 0 {
			if flag!(section.Characteristics, IMAGE_SCN_CNT_INITIALIZED_DATA) {
				raw_size = nt.OptionalHeader.SizeOfInitializedData;
			}
			else if flag!(section.Characteristics, IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
				raw_size = nt.OptionalHeader.SizeOfUninitializedData;
			}
			else {
				continue;
			}
		}

		// Write section data into it's virtual address
		let memory = module + section.VirtualAddress as u64;
		let file = file_base + section.PointerToRawData as usize;
		memcpy!(StringU8 = memory, StringU8 = file, Length = raw_size);
	}
	


	// Add it to the caches
	if !link_module_pointer(state, module as usize, name, name_length, path, path_length) {
		write_debug!(state, Info = FailedToCache);
	}
	

	// Recurisve subcall, patch the module
	write_debug!(state, Info = MappingImage);

	let old = state.image;
	state.image = module as u64;
	entry_pointer(state.base as _);
	state.image = old;


	// Successfully read and mapped image
	write_debug!(state, Success = 1);
	write_debug!(state, Value = module);
	Some(module as usize)
}



/**
	Adds a module to the loader cache or the peb if required
	Can fail if:
		Loader or link cache limits are reached
		An invalid module is given
*/
#[no_mangle]
pub unsafe fn link_module(state: &mut State, module: usize, name: CString, name_length: usize, path: CString, path_length: usize) -> bool {
	write_debug!(state, Call = LinkModule(5));
	write_debug!(state, Value = module);
	write_debug!(state, String = name, Length = name_length, Token[0]);
	write_debug!(state, Value = name_length);
	write_debug!(state, String = path, Length = path_length, Token[0]);
	write_debug!(state, Value = path_length);




	let parse_header_pointer: ParseHeader = callable!(state.base, state.parse_header);




	// Repeated code
	// Add entry to linked list
	macro_rules! insert_link  {
		($( $head:expr )*, $( $entry:expr )*) => {
			let head: &mut LIST_ENTRY = ::core::mem::transmute( $( $head )* );
			let tail: &mut LIST_ENTRY = ::core::mem::transmute(head.Blink);
			let entry: &mut LIST_ENTRY = ::core::mem::transmute( $( $entry )* );
	
			entry.Flink = head as *mut LIST_ENTRY;
			entry.Blink = tail as *mut LIST_ENTRY;

			head.Blink = entry as *mut LIST_ENTRY;
			tail.Flink = entry as *mut LIST_ENTRY;
		}
	}
	// Adds an entry to a red black binary tree
	macro_rules! insert_node  {
		($( $head:expr )*, $( $entry:expr )*) => {
			let head: &mut LIST_ENTRY = ::core::mem::transmute( $( $head )* );
			let tail: &mut LIST_ENTRY = ::core::mem::transmute(head.Blink);
			let entry: &mut LIST_ENTRY = ::core::mem::transmute( $( $entry )* );
	
			entry.Flink = head as *mut LIST_ENTRY;
			entry.Blink = tail as *mut LIST_ENTRY;

			head.Blink = entry as *mut LIST_ENTRY;
			tail.Flink = entry as *mut LIST_ENTRY;
		}
	}




	let ldr_data = transmute::<_, &mut PEB_LDR_DATA>(peb!().Ldr);
	let head_load =   (&mut ldr_data.InLoadOrderModuleList) as *mut LIST_ENTRY;
	let head_memory =   (&mut ldr_data.InMemoryOrderModuleList) as *mut LIST_ENTRY;
	let head_initialization =   (&mut ldr_data.InInitializationOrderModuleList) as *mut LIST_ENTRY;

	// I could check by comparing the name, but if this entry isn't ntdll, then something is real bad
	let ntdll_entry: &mut LDR_DATA_TABLE_ENTRY = transmute(head_memory.read().Flink.read().Flink.offset(-1));
	let ntdll_module: *mut u8 = ntdll_entry.DllBase.cast();




	// search for the hash table LdrpHashTable, which is located in ntdll
	if let None = state.ldrp_hash_table {
		write_debug!(state, Info = SearchingForLdrpHashTable);


		// Iterate through all entries finding one that is linked in the hash table
		let head =   (&mut ldr_data.InInitializationOrderModuleList) as *mut LIST_ENTRY;
		let mut flink = head;
		loop {
			let entry = transmute::<_, &mut LDR_DATA_TABLE_ENTRY>(flink.offset(-2));
			let hash_head = (&mut entry.HashLinks) as *mut LIST_ENTRY;
			let hash_flink = entry.HashLinks.Flink;

			if hash_flink != 0 as _ && hash_flink != hash_head {
				// We have found an entry that's has a valid hash list entry, which means it's a part of the hash table
				let hash_entry = hash_flink.read().Flink;
				if hash_entry == hash_head {
					let length = entry.BaseDllName.Length / 2;
					let pointer = entry.BaseDllName.Buffer;

					// Calculate the sdbm (x65599) hash, since that's what windows uses
					let hash = hash!(StringU16 = pointer, true, Length = length, Token[0]);
					let index = hash % (LDRP_HASH_TABLE_LENGTH as u64);

					// The table consist of 32 buckets, we use the index to offset back to the top of the table
					let table = hash_flink.offset(-(index as isize));

					write_debug!(state, Info = FoundLdrpHashTable(table as u64));
					state.ldrp_hash_table = Some(table as u64);
					break;
				}
			}

			flink = flink.read().Flink;
			if flink == head {
				write_debug!(state, Info = CouldNotFindLdrpHashTable);
				break;
			}
		};
	}




	// Search for the red black tree LdrpBaseAddressIndex, which is located in ntdll
	if let None = state.ldrp_index_tree {
		write_debug!(state, Info = SearchingForLdrpAddressIndex);


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
			// Parse the headers of ntdll, to traverse the sections
			let (nt, sections) = match parse_header_pointer(state, ntdll_module as usize) {
				Some((address, sections)) => (
					transmute::<_, &IMAGE_NT_HEADERS>(address),
					transmute::<_, *mut IMAGE_SECTION_HEADER>(sections)
				),
				None => {
					write_debug!(state, Failure = InvalidBuffer);
					return false;
				}
			};


			// Grab the .data section from ntdll since that's where the tree resides
			'outer: for index in 0..nt.FileHeader.NumberOfSections {
				let section: &mut IMAGE_SECTION_HEADER = transmute(sections.offset(index as isize));
				
				// TODO: compare some other way instead of this shit
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
								state.ldrp_index_tree = Some(pointer as u64);
								
								write_debug!(state, Info = FoundLdrpIndexTree(pointer as u64));
								break 'outer;
							}
						}
					}
				}				
			}
		} else {
			write_debug!(state, Info = RootIsNotBlack);
		}

		if state.ldrp_index_tree.is_none() {
			write_debug!(state, Info = CouldNotFindLdrpIndexTree);
		}
	}



	
	// Insert into our loader cache
	// The hash we use is wihtout the extensions
	let hash = hash!(String = name, true, Length = name_length, Token[0, '.']);
	let cache = (state as *mut State).offset(1).cast::<CacheEntry>();
	if state.cache_length + 1 < state.cache_max_length {
		cache.offset(state.cache_length as isize).write(CacheEntry {
			hash: hash as _,
			module: module as _,
		});
		state.cache_length += 1;
	} else {
		write_debug!(state, Failure = CacheLimitReached);
		return false;
	}




	// Insert into PEB linked lists if neccesary
	if true {
		let nt = match parse_header_pointer(state, module) {
			Some((address, _)) => (
				transmute::<_, &IMAGE_NT_HEADERS>(address)
			),
			None => {
				write_debug!(state, Failure = InvalidBuffer);
				return false;
			}
		};




		// Insert into our link cache
		let links = cache.offset(state.cache_max_length as isize).cast::<u8>();
		let link_size = (size_of::<LinkEntry>() + name_length * 2 + path_length  * 2) as u32 + 2;
		let entry: &mut LinkEntry = if state.link_size + link_size < state.link_max_size {
			let entry: &mut LinkEntry = transmute(links.offset(state.link_size as isize));
			state.link_size += link_size;
			entry.name_length = name_length as u32;
			entry.path_length = path_length as u32;
			entry
		} else {
			write_debug!(state, Failure = LinkLimitReached);
			return false;
		};
 
		// Write strings
		let entry_name: *mut u16 = (entry as *mut LinkEntry).offset(1).cast();
		let entry_path: *mut u16 = entry_name.offset(name_length as isize + 1);
		memcpy!(String = CString::U16(entry_name), String = name, Token[0]);
		memcpy!(String = CString::U16(entry_path), String = path, Token[0]);
		
		// TODO: iterate coretly over the entries, since theres no need to start directly on the head, since it's nulled.

		let data = &mut entry.data;
		let ddag = &mut entry.ddag;


		// To ensure unknown and reserved fields aren't fucking us
		// Use ntdll's entry as a base
		memcpy!(StringU8 = data as *mut _, StringU8 = ntdll_entry as *mut _, Length = size_of::<LDR_DATA_TABLE_ENTRY>());

		// Fill out known fields
		data.BaseDllName.Length = name_length as u16 - 1;
		data.BaseDllName.MaximumLength = name_length as u16 - 1;
		data.BaseDllName.Buffer = entry_name;
		data.FullDllName.Length = path_length as u16 - 1;
		data.FullDllName.MaximumLength = path_length as u16 - 1;
		data.FullDllName.Buffer = entry_path;
		data.DllBase = module as _;
		data.BaseNameHashValue = hash as _;
		data.SizeOfImage = nt.OptionalHeader.SizeOfImage as _;
		data.OriginalBase = nt.OptionalHeader.ImageBase as _;
		data.EntryPoint = if nt.OptionalHeader.AddressOfEntryPoint != 0 {
			Some(transmute(
				nt.OptionalHeader.AddressOfEntryPoint as usize + nt.OptionalHeader.ImageBase as usize
			))
		} else {
			None
		};
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

		data.DdagNode = ddag as *mut _;
		ddag.State = LdrModulesReadyToRun;
		ddag.LoadCount = -1i32 as u32;



		// Insert into hash table
		if let Some(table) = state.ldrp_hash_table {
			let table: &mut [LIST_ENTRY; LDRP_HASH_TABLE_LENGTH] = transmute(table as usize);
			
			// Calculate the hash with the extensions, since windows does that
			let hash = hash!(String = name, true, Length = name_length, Token[0]);
			let index = hash % LDRP_HASH_TABLE_LENGTH as u64;
			let head_hash = &mut table[index as usize];
			insert_link!(head_hash, &mut data.HashLinks);

			write_debug!(state, Info = InsertedIntoHashTable);
		}


		// Insert into base address index tree
		if let Some(tree) = state.ldrp_index_tree {
			let tree_offset = offset_of!(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode);


			// Walk down the tree until we find an empty leaf, to put our module
			let mut parent: &mut LDR_DATA_TABLE_ENTRY = transmute(tree as usize - tree_offset);
			write_debug!(state, Info = Exectuting);
			write_debug!(state, Value = tree);
			loop {
				let is_right;
				let child;
				
				// TODO: this thing is kinda wonky the pointers are all over the place
				let parent_node = &mut parent.BaseAddressIndexNode;
				write_debug!(state, Pointer = parent_node as *const _);

				if module < parent.DllBase as usize {
					// Go left
					child = parent_node.u.s().Left;
					write_debug!(state, Info = FailedToDeallocateBuffer(1));
					write_debug!(state, Pointer =  child as *const _);
					is_right = false;
				} else if module > parent.DllBase as usize {
					// Go Right
					child = parent_node.u.s().Right;
					write_debug!(state, Info = Relocating);
					write_debug!(state, Pointer = child  as *const _);
					is_right = true;
				} else {
					// Node is already inserted or there's another module here
					// We could overwrite by not breaking but whatev.
					write_debug!(state, Info = ResolvingImports);
					break;
				}

				if child.is_null() {
					write_debug!(state, Info = FailedToDeallocateBuffer(1111));
					// Reached a leaf, time to insert
					if is_right {
						write_debug!(state, Info = ResolvingImports);
						parent_node.u.s_mut().Right = &mut data.BaseAddressIndexNode as *mut _;
					} else {
						write_debug!(state, Info = Relocating);
						parent_node.u.s_mut().Left = &mut data.BaseAddressIndexNode as *mut _;
					}

					// The child has the opposite color of the parent, I assume same balance though
					let parent_address = &parent_node as *const _ as usize;
					let parent_balance = parent_node.ParentValue & 0b110;
					let parent_color = parent_node.ParentValue & 0b001;
					data.BaseAddressIndexNode.ParentValue = parent_address;
					data.BaseAddressIndexNode.ParentValue |= parent_balance;
					data.BaseAddressIndexNode.ParentValue |= (!parent_color) & 0b001;


					write_debug!(state, Info = InsertedIntoIndexTree);
					break;
				}

				parent = transmute(child as usize - tree_offset);
			}
		}
		

		// Insert into other linked list
		insert_link!(head_load, &mut data.InLoadOrderLinks);
		insert_link!(head_memory, &mut data.InMemoryOrderLinks);
		insert_link!(head_initialization, &mut data.u1);

		write_debug!(state, Info = InsertedIntoLinkedList);
	}


	write_debug!(state, Success = 0);
	true
}




#[no_mangle]
pub unsafe fn resolve_function(state: &mut State, module: usize, export_rva: usize, export_size: usize, ordinal: Option<usize>, name: Option<CString>, hint: Option<u32>) -> Option<usize> {
	write_debug!(state, Call = ResolveFunction(6));
	write_debug!(state, Value = module);
	write_debug!(state, Value = export_rva);
	write_debug!(state, Value = export_size);
	write_debug!(state, Value = Option = ordinal);
	write_debug!(state, String = Option = name, Token[0, '.']);
	write_debug!(state, Value = Option = hint);



	
	let parse_header_pointer: ParseHeader = callable!(state.base, state.parse_header);
	let find_module_pointer: FindModule = callable!(state.base, state.find_module);
	let resolve_function_pointer: ResolveFunction = callable!(state.base, state.resolve_function);




	// Get export table pointers
	if export_rva == 0 {
		write_debug!(state, Failure = InvalidExports);
		return None;
	}
	let exports: &IMAGE_EXPORT_DIRECTORY = transmute(module + export_rva as usize);
	let function_ptr: *const u32 = (module + exports.AddressOfFunctions as usize) as _;
	let name_ptr: *const u32 = (module + exports.AddressOfNames as usize) as _;
	let ordinal_ptr: *const u16 = (module + exports.AddressOfNameOrdinals as usize) as _;


	// Try to find the function pointer
	let mut function_index: Option<u32> = None;
	let ordinal = ordinal.unwrap_or(0);

	if flag!(ordinal, IMAGE_ORDINAL_FLAG as usize) {
		// Import by ordinal
		function_index = Some((ordinal & 0xffff) as u32 - exports.Base);
	} else if let Some(name) = name {
		// Import by name
		if let Some(hint) = hint {
			// Try to use hint
			if hint < exports.NumberOfNames {
				// Get export name
				let export_offset = name_ptr.offset(hint as isize).read() as usize;
				if export_offset != 0 {
					let export_name = (module + export_offset) as *const u8;

					let is_equal = string_eq!(String = name, String = CString::U8(export_name), true, Token[0, '.']);
					if is_equal {
						// Hint was valid
						function_index = Some(ordinal_ptr.offset(hint as isize).read() as u32);
					}
				}
			}
		}
		
		if let None = function_index {
			
			/*
			// If hint is invalid then do a binary search
			let mut min = 0;
			let mut max = exports.NumberOfNames - 1;

			while max >= min {
				let mean = (min + max) / 2;

				// Get export name
				let export_offset = name_ptr.offset(mean as isize).read() as usize;
				write_debug!(state, Value = export_offset);
				if export_offset == 0 {
					write_debug!(state, Info = ResolvingImports);
					// This shouldn't happen
					break;
				}
				let export_name = (module + export_offset) as *const u8;

				// Compare import name and export name
				let status = string_cmp!(String = name, String = CString::U8(export_name), false, Token[0, '.']);
				if status == Strcmp::LeftGreater || status == Strcmp::LeftLonger {
					// Check upper half
					min = mean + 1;
				}
				else if status == Strcmp::RightGreater || status == Strcmp::RightLonger {
					// Check lower half
					max = mean - 1;
				}
				else {
					// Matching export found
					function_index = Some(ordinal_ptr.offset(mean as isize).read() as u32);
					break;
				}
			}
			*/

			// TODO: tempory brute force, since some wierd issues came up, should revert back soon
			for i in 0..exports.NumberOfNames {
				// Get export name
				let export_offset = name_ptr.offset(i as isize).read() as usize;
				//write_debug!(state, Value = export_offset);
				if export_offset == 0 {
					write_debug!(state, Info = ResolvingImports);
					// This shouldn't happen
					break;
				}
				let export_name = (module + export_offset) as *const u8;
				
				//write_debug!(state, Value = i);
				//write_debug!(state, StringU8 = export_name, Token[0, '.']);
				// Compare import name and export name
				let status = string_cmp!(String = name, String = CString::U8(export_name), false, Token[0, '.']);
				if status == Strcmp::Equal {
					// Matching export found
					function_index = Some(ordinal_ptr.offset(i as isize).read() as u32);
					break;
				}
			}
		}
	}
	
	// Try to use the function index to find the actual function
	if let Some(index) = function_index {
		if index < exports.NumberOfFunctions {
			// Function is found
			let offset = function_ptr.offset(index as isize).read() as usize;
			if offset >= export_rva as usize && offset < (export_rva + export_size) as usize {
				// Function is a forwarder string
				write_debug!(state, Info = ImportForwarded);
		
				// Load dependent module
				let module_name = (module + offset) as *const u8;
				let module_name_length = string_len!(StringU8 = module_name, Token[0, '.']);
				let module = match find_module_pointer(state, CString::U8(module_name), module_name_length) {
					Some(module) => module,
					None => {
						// Could not resolve forwarded module
						write_debug!(state, Failure = InvalidModule);
						return None;
					}
				};
		
				// Parse headers
				let entry = match parse_header_pointer(state, module) {
					Some((address, _)) => (
						transmute::<_, &IMAGE_NT_HEADERS>(address).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
					),
					None => {
						write_debug!(state, Failure = InvalidHeader);
						return None;
					}
				};
				let export_rva = entry.VirtualAddress as usize;
				let export_size = entry.Size as usize;
		
				// Try to resolve function
				let function_name = module_name.offset(string_len!(StringU8 = module_name, Token[0, '.']) as isize + 1);
				match resolve_function_pointer(state, module, export_rva, export_size, None, Some(CString::U8(function_name)), None) {
					Some(address) => {
						write_debug!(state, Success = 1);
						write_debug!(state, Value = address);
						return Some(address); 
					}
					None => {
						write_debug!(state, Failure = NotFound);
						return None;
					}
				}
			} else {
				let address = module + offset;
				write_debug!(state, Success = 1);
				write_debug!(state, Value = address);
				return Some(address); 
			}
		}
	}

	// Function is not found
	write_debug!(state, Failure = NotFound);
	None
}




#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct IO_STATUS_BLOCK64 {
	Status: u64,
	Information: u64,
}
#[no_mangle]
pub unsafe fn read_file(state: &mut State, path: *const u16, length: usize) -> Option<usize> {
	write_debug!(state, Call = ReadFile(2));
	write_debug!(state, StringU16 = path, Length = length);
	write_debug!(state, Value = length);




	// TODO: possible error with file_path on native x86
	let file_path = Aligned::<A8, _>(UNICODE_STRING64 {
		Length: (length * size_of::<u16>()) as u16,
		MaximumLength: (length * size_of::<u16>()) as u16,
		Buffer: path as u64,
	});

	// Ensure correct alignment of data
	//let file_path: EitherArch<Aligned::<A8, OBJECT_ATTRIBUTES64>, OBJECT_ATTRIBUTES>;
	let attributes: EitherArch<Aligned::<A8, OBJECT_ATTRIBUTES64>, OBJECT_ATTRIBUTES>;
	let io_status: EitherArch<Aligned::<A8, IO_STATUS_BLOCK64>, IO_STATUS_BLOCK>;
	match cpu_mode!() {
		CpuMode::EmulatedX86 | CpuMode::NativeX64 => {
			attributes = EitherArch::X64(
				Aligned::<A8, _>(OBJECT_ATTRIBUTES64 {
					Length: size_of::<OBJECT_ATTRIBUTES64>() as u32,
					RootDirectory: 0 as _,
					ObjectName: &*file_path as *const _ as u64,
					Attributes: 0,
					SecurityDescriptor: 0 as _,
					SecurityQualityOfService: 0 as _,
				})
			);

			io_status = EitherArch::X64(
				Aligned::<A8, _>(IO_STATUS_BLOCK64 {
					Status: 0,
					Information: 0,
				})
			);
		}
		#[cfg(target_arch = "x86")]
		CpuMode::NativeX86 => {
			attributes = EitherArch::X86(
				OBJECT_ATTRIBUTES {
					Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
					RootDirectory: 0 as _,
					ObjectName: transmute(&*file_path),
					Attributes: 0,
					SecurityDescriptor: 0 as _,
					SecurityQualityOfService: 0 as _,
				}
			);
			io_status = EitherArch::X86(
				IO_STATUS_BLOCK {
					u: transmute(0 as *const u8),
					Information: 0,
				}
			);
		}
		#[cfg(target_arch = "x86_64")]
		CpuMode::NativeX86 => {
			// This should never happen lol
			write_debug!(state, Failure = CpuModeInvalid(0x1b));
			return None;
		}
		CpuMode::Unknown(mode) => {
			// This should never happen lol
			write_debug!(state, Failure = CpuModeInvalid(mode));
			return None;
		}
	}

	let attributes_ptr: *const u8 = match &attributes {
		EitherArch::X64(attributes) => transmute(attributes),
		EitherArch::X86(attributes) => transmute(attributes),
	};
	let io_status_ptr: *const u8 = match &io_status {
		EitherArch::X64(io_status) => transmute(io_status),
		EitherArch::X86(io_status) => transmute(io_status),
	};



	// Open the file
	let handle: i64 = -1i64;
	let mut status = syscall!(
		state.syscall_open_file, // NtOpenFile
		&handle as *const _, // FileHandle
		GENERIC_READ | SYNCHRONIZE, // DesiredAccess
		attributes_ptr, // ObjectAttributes
		io_status_ptr, // IoStatusBlock
		FILE_SHARE_READ, // ShareAccess
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT// OpenOptions
	);
	if !ntstatus_valid!(status) || handle == -1i64 {
		// Failed to open the file, it might not exist
		write_debug!(state, Failure = FailedToOpenFile(status));
		return None;
	}


	// Get file size
	let information = Aligned::<A8, _>(FILE_STANDARD_INFORMATION {
		AllocationSize: transmute(0_u64),
		EndOfFile: transmute(0_u64),
		DeletePending: 0 as _,
		Directory: 0 as _,
		NumberOfLinks: 0 as _,
	});
	status = syscall!(
		state.syscall_query_information, // NtQueryInformationFile
		handle, // FileHandle
		io_status_ptr, // IoStatusBlock 
		&information as *const _, // FileInformation
		size_of::<FILE_STANDARD_INFORMATION>(), // Length
		FileStandardInformation // FileInformationClass
	);
	let file_size: u64 = *information.EndOfFile.QuadPart() as u64;
	if !ntstatus_valid!(status) || file_size == 0 {
		// Failed to get file size
		write_debug!(state, Failure = FailedToGetFileSize(status));
		return None;
	}

	// Unallocate old filebuffer if it's too small, otherwise reuse the buffer
	if let Some(size) = state.file_buffer_size {
		if state.file_buffer.is_some() {
			if (size as u64) < file_size {
				let region_size = 0;
				status = syscall!(
					state.syscall_virtual_free, //NtFreeVirtualMemory
					CURRENT_PROCESS, // ProcessHandle
					&state.file_buffer as *const _, // BaseAddress
					&region_size as *const _, // RegionSize
					MEM_RELEASE // FreeType
				);
				if !ntstatus_valid!(status) {
					// Failed to free buffer, this is not fatal so continue
					write_debug!(state, Info = FailedToDeallocateBuffer(status));
				}
				state.file_buffer = None;
				state.file_buffer_size = None;
			}
		}
	}



	// Allocate new buffer to hold the file content if old buffer does not exist
	if let None = state.file_buffer {
		let mut allocation_base: u64 = 0;
		status = syscall!(
			state.syscall_virtual_allocate, // NtAllocateVirtualMemory
			CURRENT_PROCESS, // ProcessHandle
			&mut allocation_base as *mut _, // BaseAddress
			0, // ZeroBits
			&file_size as *const _, // RegionSize
			MEM_COMMIT | MEM_RESERVE, // AllocationType
			PAGE_READWRITE // Protect
		);
		if !ntstatus_valid!(status) || allocation_base == 0 {
			// Failed to allocate buffer
			write_debug!(state, Failure = FailedToAllocateBuffer(status));
			return None;
		}
		state.file_buffer = Some(allocation_base as u64);
		state.file_buffer_size = Some(file_size as u32);
	}

	// Read the file into the buffer
	let buffer = match state.file_buffer {
		Some(buffer) => buffer,
		None => {
			// This shouldn't happen
			write_debug!(state, Failure = InvalidBuffer);
			return None;
		}
	};
	status = syscall!(
		state.syscall_read_file, // NtReadFile
		handle, // FileHandle
		0, // Event
		0, // ApcRoutine
		0, // ApcContext
		io_status_ptr, // IoStatusBlock
		buffer, // Buffer
		file_size, // Length
		0, // ByteOffset
		0 // Key
	);
	if !ntstatus_valid!(status) {
		// Failed to read file
		write_debug!(state, Failure = FailedToReadFile(status));
		return None;
	}


	write_debug!(state, Success = 1);
	write_debug!(state, Value = buffer);
	Some(buffer as usize)
}
#[no_mangle]
pub unsafe fn stub() {
	// For some reason the pdb parsin li sucks ass so this is needed
	// TODO: this is temp
}

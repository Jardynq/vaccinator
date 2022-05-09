use std::mem::size_of;
use nt_syscall::*;
use interface::*;




pub trait StateAbstract where Self: Sized {
	fn new(base: u64, cache_length: u32, link_size: u32, path: Option<u64>, debug: Option<u64>, options: Vec<Options>) -> Option<Self>;
	fn size(&self) -> usize;
	fn initialize_binary(&mut self, shuffle: bool, mode: Mode) -> Vec<u8>;
}

// TODO: move this into interface
impl StateAbstract for State {
	fn new(base: u64, cache_length: u32, link_size: u32, path: Option<u64>, debug: Option<u64>, mut options: Vec<Options>) -> Option<Self> {
		let ordinals = get_indices_x64!(
			22000,
			NtCreateThreadEx, 
			NtProtectVirtualMemory, 
			NtAllocateVirtualMemory, 
			NtFreeVirtualMemory, 
			NtOpenFile, 
			NtReadFile, 
			NtQueryInformationFile
		);
		if !are_indices_valid!(ordinals) {
			return None;
		}
		
		let file_path = match path {
			Some(path) => {
				options.push(Options::UseFilePath);
				path
			}
			None => 0,
		};

		Some(Self {
			base: 0,
			
			heavens_gate: 0,
			entry: 0,
			parse_header: 0,
			find_module: 0,
			load_module: 0,
			map_module: 0,
			link_module: 0,
			resolve_function: 0,
			read_file: 0,
			
			syscall_create_thread: ordinals[0],
			syscall_virtual_protect: ordinals[1],
			syscall_virtual_allocate: ordinals[2],
			syscall_virtual_free: ordinals[3],
			syscall_open_file: ordinals[4],
			syscall_read_file: ordinals[5],
			syscall_query_information: ordinals[6],

			options: options.iter().fold(0, |value, flag| value | *flag as u32),

			path_pointer: path,

			recovery: 0,

			image: base,
			depth: 0,

			file_buffer: None,
			file_buffer_size: None,

			ldrp_hash_table: None,
			ldrp_index_tree: None,

			debug_head: debug,

			cache_max_length: cache_length,
			cache_length: 0,

			link_max_size: link_size,
			link_size: 0,
		})
	}

	fn size(&self) -> usize {
		size_of::<Self>() + 
		self.cache_max_length as usize * size_of::<CacheEntry>() +
		self.link_max_size as usize
	}

	fn initialize_binary(&mut self, shuffle: bool, mode: Mode) -> Vec<u8> {
		let mut binary = Vec::new();
		let mut indices = (0..=8).collect::<Vec<usize>>();
		if shuffle {
			let mut state = oorandom::Rand32::new(timestamp!());

			for index in (1..indices.len()).rev() {
				let random = (state.rand_float() * (index as f32 + 1.0)).floor() as usize;
				let temp = indices[index];
				indices[index] = indices[random];
				indices[random] = temp;
			}
		}

		let state_size = self.size() as u32;

		if mode == Mode::X64IntoX64Native || mode == Mode::X64IntoX86Emulated {
			// x64 image
			for index in indices {
				match index {
					0 => {
						if mode == Mode::X64IntoX86Emulated {
							println!("{:x} heavens gate", binary.len() + state_size as usize);

							let heavens_gate = include_bytes!("../shared/i686/loader.dll.heavens_gate").to_vec();
							self.heavens_gate = binary.len() as u32 + state_size;
							binary.extend(heavens_gate);
						}
					}
					1 => {
						println!("{:x} entry", binary.len() + state_size as usize);


						let entry = include_bytes!("../shared/x86_64/loader.dll.entry").to_vec();
						self.entry = binary.len() as u32 + state_size;
						binary.extend(entry);
					}
					2 => {
						println!("{:x} parse header", binary.len() + state_size as usize);

						let parse_header = include_bytes!("../shared/x86_64/loader.dll.parse_header").to_vec();
						self.parse_header = binary.len() as u32 + state_size;
						binary.extend(parse_header);
					}
					3 => {
						println!("{:x} find module", binary.len() + state_size as usize);

						let find_module = include_bytes!("../shared/x86_64/loader.dll.find_module").to_vec();
						self.find_module = binary.len() as u32 + state_size;
						binary.extend(find_module);
					}
					4 => {
						println!("{:x} load module", binary.len() + state_size as usize);

						let load_module = include_bytes!("../shared/x86_64/loader.dll.load_module").to_vec();
						self.load_module = binary.len() as u32 + state_size;
						binary.extend(load_module);
					}
					5 => {
						println!("{:x} map module", binary.len() + state_size as usize);

						let map_module = include_bytes!("../shared/x86_64/loader.dll.map_module").to_vec();
						self.map_module = binary.len() as u32 + state_size;
						binary.extend(map_module);
					}
					6 => {
						println!("{:x} link module", binary.len() + state_size as usize);
						let link_module = include_bytes!("../shared/x86_64/loader.dll.link_module").to_vec();
						self.link_module = binary.len() as u32 + state_size;
						binary.extend(link_module);
					}
					7 => {
						println!("{:x} resolve function", binary.len() + state_size as usize);

						let resolve_function = include_bytes!("../shared/x86_64/loader.dll.resolve_function").to_vec();
						self.resolve_function = binary.len() as u32 + state_size;
						binary.extend(resolve_function);
					}
					8 => {
						println!("{:x} read file", binary.len() + state_size as usize);

						let read_file = include_bytes!("../shared/x86_64/loader.dll.read_file").to_vec();
						self.read_file = binary.len() as u32 + state_size;
						binary.extend(read_file);
					}
					_ => (),
				}
			}
		} else {
			// x86 image
			for index in indices {
				match index {
					0 => {
						if mode == Mode::X86IntoX64Native {
							println!("{:x} heavens gate", binary.len() + state_size as usize);
							let heavens_gate = include_bytes!("../shared/x86_64/loader.dll.heavens_gate").to_vec();
							self.heavens_gate = binary.len() as u32 + state_size;
							binary.extend(heavens_gate);
						}
					}
					1 => {
						println!("{:x} entry", binary.len() + state_size as usize);
						let entry = include_bytes!("../shared/i686/loader.dll.entry").to_vec();
						self.entry = binary.len() as u32 + state_size;
						binary.extend(entry);
					}
					2 => {
						println!("{:x} parse header", binary.len() + state_size as usize);

						let parse_header = include_bytes!("../shared/i686/loader.dll.parse_header").to_vec();
						self.parse_header = binary.len() as u32 + state_size;
						binary.extend(parse_header);
					}
					3 => {
						println!("{:x} find module", binary.len() + state_size as usize);
						let find_module = include_bytes!("../shared/i686/loader.dll.find_module").to_vec();
						self.find_module = binary.len() as u32 + state_size;
						binary.extend(find_module);
					}
					4 => {
						println!("{:x} load module", binary.len() + state_size as usize);
						let load_module = include_bytes!("../shared/i686/loader.dll.load_module").to_vec();
						self.load_module = binary.len() as u32 + state_size;
						binary.extend(load_module);
					}
					5 => {
						println!("{:x} map module", binary.len() + state_size as usize);
						let map_module = include_bytes!("../shared/i686/loader.dll.map_module").to_vec();
						self.map_module = binary.len() as u32 + state_size;
						binary.extend(map_module);
					}
					6 => {
						println!("{:x} link module", binary.len() + state_size as usize);
						let link_module = include_bytes!("../shared/i686/loader.dll.link_module").to_vec();
						self.link_module = binary.len() as u32 + state_size;
						binary.extend(link_module);
					}
					7 => {
						println!("{:x} resolve function", binary.len() + state_size as usize);
						let resolve_function = include_bytes!("../shared/i686/loader.dll.resolve_function").to_vec();
						self.resolve_function = binary.len() as u32 + state_size;
						binary.extend(resolve_function);
					}
					8 => {
						println!("{:x} read file", binary.len() + state_size as usize);
						let read_file = include_bytes!("../shared/i686/loader.dll.read_file").to_vec();
						self.read_file = binary.len() as u32 + state_size;
						binary.extend(read_file);
					}
					_ => (),
				}
			}
		}

		binary
	}
}

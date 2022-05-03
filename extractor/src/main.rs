#![feature(with_options)]

use std::fs::File;
use std::path::PathBuf;
use std::io::{
	Read,
	Write,
};
use std::mem::{
	transmute,
	size_of,
};


use winapi::um::winnt::*;
use log::{
	info,
	warn,
	error,
};
use clap::{
	Clap,
	AppSettings,
	ValueHint,
};
use pdb::{
	FallibleIterator,
	SymbolData,
	SectionOffset,
};
use anyhow::{
	Error,
	anyhow,
};




#[derive(Clap, Debug, Clone)]
#[clap(version = "0.1")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Arguments {
    /// Path to the image file
	#[clap(short, long, parse(from_os_str), value_hint = ValueHint::AnyPath)]
    image: PathBuf,

    /// Path to the pdb file of the image
	#[clap(short, long, parse(from_os_str), value_hint = ValueHint::AnyPath)]
    pdb: Option<PathBuf>,
	
	/// Path to output folder
	#[clap(short, long, parse(from_os_str), value_hint = ValueHint::AnyPath)]
	out: PathBuf,
	
	/// Silence ouput
	#[clap(long)]
	silent: bool,

	/// Trim some name mangling from the symbol
	/// For some reason some symbols get slighty mangled no matter what
	#[clap(long)]
	trim: bool,

    /// Symbols to dump
	#[clap(short, long, required = true, min_values = 1)]
    symbols: Vec<String>,

}




#[derive(Clone, Debug)]
struct Symbol {
	address: usize,
	name: String,
}


enum Arch {
	X64(IMAGE_NT_HEADERS64),
	X86(IMAGE_NT_HEADERS32),
}
struct Image {
	arch: Arch,
	sections: Vec<IMAGE_SECTION_HEADER>,
	file: Vec<u8>,
}




fn main() -> Result<(), Error> {
	let args: Arguments = Arguments::parse();
	
	env_logger::builder()
		.filter(None, if args.silent {
				log::LevelFilter::Off
			} else {
				log::LevelFilter::max()
			}
		)
		.init();


	let image = unsafe { load_image(&args.image)? };
	let image_limit = unsafe {
		image.file.as_ptr().offset(image.file.len() as isize) as usize - 100
	};
	let image_name = args.image.file_name()
		.ok_or_else(|| {
			anyhow!("Failed to parse image name from path buffer")
		})?
		.to_str()
		.ok_or_else(|| {
			anyhow!("Failed to parse image name from os string")
		})?
		.to_string();


	match &args.pdb {
		Some(path) => {
			info!("Using pdb");
			let symbols = get_pdb_symbols(&image, path, args.trim)?;
			dump_symbols(symbols, image_name, image_limit, &args);
		}
		None => {
			info!("No pdb given, using image headers");
			let symbols = get_image_symbols(&image)?;
			dump_symbols(symbols, image_name, image_limit, &args);
		}
	};

	Ok(())
}




fn dump_symbols(symbols: Vec<Symbol>, image_name: String, limit: usize, args: &Arguments) {
	let mut to_find = args.symbols.clone();
	if to_find.len() == 1 {
		let split: Vec<&str> = to_find[0].split_whitespace().collect();
		if split.len() > 1 {
			to_find = split.iter()
				.map(|symbol| 
					symbol.to_string()
				)
				.collect();
		}
	}

	for (index, symbol) in symbols.iter().enumerate() {
		if to_find.len() == 0 {
			break;
		}

		let mut found = None;
		for (symbol_index, find) in to_find.iter().enumerate() {
			if find == &symbol.name {
				let size = symbols.get(index + 1).and_then(|next| {
					Some(next.address - symbol.address)
				});

				let dump = |address: usize, bytes: &mut Vec<u8>| -> bool {
					if address >= limit {
						true
					} else {
						let byte = unsafe {
							(address as *const u8).read()
						};
						bytes.push(byte);
						false
					}
				};

				let mut bytes = Vec::new();
				if let Some(size) = size {
					for index in symbol.address..(symbol.address + size) {
						if dump(index, &mut bytes) {
							break;
						}
					}
				} else {
					loop {
						if dump(index, &mut bytes) {
							break;
						}
					}
				}


				let mut out = args.out.clone();
				let out_name = image_name.clone() + "." + &symbol.name;
				out.push(out_name);
				let mut file = File::with_options()
					.create(true)
					.write(true)
					.append(false)
					.truncate(true)
					.open(&out);
				
				info!("Dumping symbol '{}'", symbol.name);
				match file.as_mut() {
					Ok(file) => {
						if let Err(error) = file.write_all(bytes.as_slice()) {
							error!("Failed to write file '{}'\n{}", out.to_str().unwrap_or("_"), error);
							break;
						};
					}
					Err(error) => {
						error!("Failed to open file '{}'\n{}", out.to_str().unwrap_or("_"), error);
						break;
					}
				}

				found = Some(symbol_index);
				break;
			}
		}

		if let Some(index) = found {
			to_find.remove(index);
		}
	}
	
	for symbol in to_find {
		warn!("The symbol '{}' was not found in the image", symbol);
	}
}




unsafe fn load_image(path: &PathBuf) -> Result<Image, Error> {	
	let mut file = Vec::new();
	File::open(path)?.read_to_end(&mut file)?;

	
	let mut req_length = size_of::<IMAGE_DOS_HEADER>();
	if file.len() <= req_length {
		return Err(anyhow!("Image too small for dos header"));
	}
	let dos: &IMAGE_DOS_HEADER = transmute(file.as_ptr());
	if dos.e_magic != IMAGE_DOS_SIGNATURE {
		return Err(anyhow!("Invalid dos image header"));
	}


	req_length += size_of::<IMAGE_NT_HEADERS64>();
	if file.len() <= req_length {
		return Err(anyhow!("Image too small for nt header"));
	}
	let nt_pointer = file.as_ptr().offset(dos.e_lfanew as isize);
	let nt64: &IMAGE_NT_HEADERS64 = transmute(nt_pointer);
	let nt32: &IMAGE_NT_HEADERS32 = transmute(nt_pointer);
	if nt64.Signature != IMAGE_NT_SIGNATURE {
		return Err(anyhow!("Invalid nt image header"));
	}


	req_length += size_of::<IMAGE_FILE_HEADER>();
	if file.len() <= req_length {
		return Err(anyhow!("Image too small for file header"));
	}
	let section_count = nt64.FileHeader.NumberOfSections as usize;
	let optional_size = nt64.FileHeader.SizeOfOptionalHeader as usize;


	req_length += optional_size;
	if file.len() <= req_length {
		return Err(anyhow!("Image too small for optional header"));
	}


	let is_valid_x86_64 = {
		nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
		nt64.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64
	};
	let is_valid_i686 = {
		nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
		nt64.FileHeader.Machine == IMAGE_FILE_MACHINE_I386
	};


	let arch;
	if is_valid_x86_64 {
		info!("Image is x86_64");
		arch = Arch::X64(nt64.clone());
	} else if is_valid_i686 {
		info!("Image is i686");
		arch = Arch::X86(nt32.clone()); 
	} else {
		return Err(anyhow!("Invalid image architecture"));
	}


	req_length += size_of::<IMAGE_SECTION_HEADER>() * section_count as usize;
	if file.len() <= req_length {
		return Err(anyhow!("Image too small for section headers"));
	}

	let sections_address = nt_pointer as usize + size_of::<u32>() + size_of::<IMAGE_FILE_HEADER>() + optional_size;
	let sections_pointer = sections_address as *const IMAGE_SECTION_HEADER;

	let mut sections = Vec::new();
	for index in 0..section_count {
		sections.push(
			sections_pointer.offset(index as isize).read()
		);
	}


	Ok(Image {
		arch,
		sections,
		file,
	})
}




fn get_image_symbols(image: &Image) -> Result<Vec<Symbol>, Error> {
	/*
	match image.arch {
		Arch::X64(nt) => {
			let directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
		}
	}
	*/


	
	unimplemented!()
}




fn get_pdb_symbols(image: &Image, path: &PathBuf, trim: bool) -> Result<Vec<Symbol>, Error> {
    let mut pdb = pdb::PDB::open(File::open(path)?)?;

    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;

	let mut ordered: Vec<Symbol> = Vec::new();
    for symbol in symbol_table.iter().iterator() {
		if let Ok(symbol) = symbol {
			let name: String;
			let offset: Option<SectionOffset>;
			match symbol.parse() {
				Ok(SymbolData::Data(symbol)) => {
					name = format!("{}", symbol.name);
					offset = symbol.offset.to_section_offset(&address_map);
				}
				Ok(SymbolData::Procedure(symbol)) => {
					name = format!("{}", symbol.name);
					offset = symbol.offset.to_section_offset(&address_map);
				}
				Ok(SymbolData::Public(symbol)) => {
					name = format!("{}", symbol.name);
					offset = symbol.offset.to_section_offset(&address_map);
				}
				Ok(SymbolData::Thunk(symbol)) => {
					name = format!("{}", symbol.name);
					offset = symbol.offset.to_section_offset(&address_map);
				}
				Ok(SymbolData::Block(symbol)) => {
					name = format!("{}", symbol.name);
					offset = symbol.offset.to_section_offset(&address_map);
				}
				Ok(SymbolData::Label(symbol)) => {
					name = format!("{}", symbol.name);
					offset = symbol.offset.to_section_offset(&address_map);
				}
				Ok(SymbolData::SeparatedCode(symbol)) => {
					name = format!("");
					offset = symbol.offset.to_section_offset(&address_map);
				}
				_ => {
					continue;
				}
			}

			if let Some(offset) = offset {
				if offset.section == 0 {
					continue;
				}

				if let Some(section) = image.sections.get(offset.section as usize - 1) {
					let data_offset = section.PointerToRawData as usize;
					if data_offset >= image.file.len() {
						continue;
					}


					let pointer = unsafe {
						image.file.as_ptr().offset(data_offset as isize + offset.offset as isize)
					};

					ordered.push(Symbol {
						address: pointer as usize,
						name: if trim {
							let mut cleaned = name.trim_matches('_');
							if let Some(index) = cleaned.find('@') {
								cleaned = &cleaned[0..index];
							};
							cleaned.to_string()
						} else { name },
					})
				}
			}
		}
    }
	ordered.sort_by(|a, b| {
		a.address.cmp(&b.address)
	});


	Ok(ordered)
}

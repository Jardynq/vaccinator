#![no_std]
#![feature(unchecked_math)]
#![allow(dead_code)]

use winapi::shared::{
	minwindef::*,
	ntdef::RTL_BALANCED_NODE,
};
use ntapi::ntldr::{
	LDR_DATA_TABLE_ENTRY,
	LDR_DDAG_NODE,
};

mod tools;
pub use tools::*;

mod debug;
pub use debug::*;



pub const CURRENT_PROCESS: u64 = u64::MAX;
pub const CURRENT_THREAD: u64 = u64::MAX - 1;

pub const KUSER_ADDRESS: u64 = 0x7ffe0000;

pub const LDRP_HASH_TABLE_LENGTH: usize = 32;


pub const FILEPATH_BUFFER_SIZE: usize = MAX_PATH + 0x10;


// The compiler thinks it's sooo fucking smart, and optimizes strings and chars into shit
// So instead i trick it into thinking that these are just integers instead :5head:
macro_rules! segmentize  {
	( U8 : $( $a:expr , $b:expr , $c:expr , $d:expr, $e:expr , $f:expr , $g:expr , $h:expr ),* ) => {
		[ $( 
			(($a as u64) << 0x0) + (($b as u64) << 0x8) + (($c as u64) << 0x10) + (($d as u64) << 0x18) +
			(($e as u64) << 0x20) + (($f as u64) << 0x28) + (($g as u64) << 0x30) + (($h as u64) << 0x38) 
		),* ]
	};
	( U16 : $( $a:expr , $b:expr , $c:expr , $d:expr ),* ) => {
		segmentize!( U8 : $( $a , 0 , $b , 0 , $c , 0 , $d, 0 ),* )
	};
}
pub const STRING_SEGMENT_LENGTH: isize = 4;
pub const STRING_DLL: u64 = segmentize!(U16: '.', 'd', 'l', 'l')[0];
pub const STRING_PREFIX: u64 = segmentize!(U16: '\\', '?', '?', '\\')[0];

pub const STRING_SYSTEM32_LENGTH: isize = 10;
pub const STRING_SYSTEM32: [u64; 3] = segmentize!(U16: '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 0, 0);
pub const STRING_SYSWOW64_LENGTH: isize = 10;
pub const STRING_SYSWOW64: [u64; 3] = segmentize!(U16: '\\', 's', 'y', 's', 'w', 'o', 'w', '6', '4', '\\', 0, 0);

// TODO: use the segmentize trick from above instead of the hashes
pub const STRING_API: u64 = segmentize!(U16: 'a', 'p', 'i', '-')[0];
pub const STRING_EXT: u64 = segmentize!(U16: 'e', 'x', 't', '-')[0];
pub const STRING_PATH_LENGTH: usize = 5;
pub const STRING_PATH: [u64; 2] = segmentize!(U16: 'p', 'a', 't', 'h', '=', 0, 0, 0);
pub const STRING_SYSTEMROOT_LENGTH: usize = 11;
pub const STRING_SYSTEMROOT: [u64; 3] = segmentize!(U16: 's', 'y', 's', 't', 'e', 'm', 'r', 'o', 'o', 't', '=', 0);
pub const STRING_WINDIR_LENGTH: usize = 7;
pub const STRING_WINDIR: [u64; 2] = segmentize!(U16: 'w', 'i', 'n', 'd', 'i', 'r', '=', 0);

pub const STRING_DOTDATA_LENGTH: usize = 5;
pub const STRING_DOTDATA: u64 = segmentize!(U8: '.', 'd', 'a', 't', 'a', 0, 0, 0)[0];



pub const fn const_hash(string: &str) -> u64 {
	let mut hash: u64 = 0;
	let bytes = string.as_bytes();
	let mut index = 0 ;
	while index < bytes.len() {
		hash = (bytes[index] as u64).wrapping_add(hash << 6).wrapping_add(hash << 16).wrapping_sub(hash);
		index += 1;
	}
	hash
}
pub const API_PREFIX_HASH: u64 = const_hash("API-");
pub const EXT_PREFIX_HASH: u64 = const_hash("EXT-");
pub const PREFIX_LENGTH: usize = 4;

pub const ENVIRONMENT_PATH_HASH: u64 = const_hash("PATH=");
pub const ENVIRONMENT_PATH_LENGTH: usize = 5;
pub const ENVIRONMENT_SYSTEMROOT_HASH: u64 = const_hash("SYSTEMROOT=");
pub const ENVIRONMENT_SYSTEMROOT_LENGTH: usize = 11;
pub const ENVIRONMENT_WINDIR_HASH: u64 = const_hash("WINDIR=");
pub const ENVIRONMENT_WINDIR_LENGTH: usize = 7;



pub type TlsCallback = unsafe extern "system" fn (HMODULE, DWORD, LPVOID);
pub type DllMain = unsafe extern "system" fn (HMODULE, DWORD, LPVOID) -> DWORD;

pub type HeavensGateX64 = unsafe extern "system" fn (u64);
pub type HeavensGateX86 = unsafe extern "system" fn (u32);
pub type EntryX64 = unsafe extern "system" fn (u64);
pub type EntryX86 = unsafe extern "system" fn (u32);
#[cfg(target_arch = "x86_64")]
pub type Entry = EntryX64;
#[cfg(target_arch = "x86")]
pub type Entry = EntryX86;

pub type ParseHeader = unsafe fn (&mut State, usize) -> Option<(usize, usize)>;
pub type FindModule = unsafe fn (&mut State, CString, usize) -> Option<usize>;
pub type LoadModule = unsafe fn (&mut State, CString, usize) -> Option<usize>;
pub type MapModule = unsafe fn (&mut State, CString, usize, CString, usize) -> Option<usize>;
pub type LinkModule = unsafe fn (&mut State, usize, CString, usize, CString, usize) -> bool;
pub type ResolveFunction = unsafe fn (&mut State, usize, usize, usize, Option<usize>, Option<CString>, Option<u32>) -> Option<usize>;
pub type ReadFile = unsafe fn (&mut State, *const u16, usize) -> Option<usize>;




#[derive(Clone, Copy)]
pub struct Fat<T> {
	pub pointer: *mut T,
	pub length: u32,
}

#[derive(Clone, Copy, PartialEq)]
pub enum CString {
	U8(*const u8),
	U16(*const u16),
}
impl CString {
	pub fn is_null(&self) -> bool {
		match self {
			Self::U8(ptr) => ptr.is_null(),
			Self::U16(ptr) => ptr.is_null(),
		}
	}
}

/*
#[derive(Clone, Copy, PartialEq)]
pub enum CString {
	U8(Fat<u8>),
	U16(Fat<u16>),
}
*/


#[derive(Clone, Copy, PartialEq)]
pub enum EitherArch<T, U> {
	X64(T),
	X86(U),
}




#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
	X64IntoX64Native,
	X86IntoX86Native,
	X86IntoX64Native,
	X86IntoX86Emulated,
	X64IntoX86Emulated,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Options {
	UseFilePath = 1 << 0,
	ReleaseThread = 1 << 1,
	StripMeta = 1 << 2,
	HideThread = 1 << 3,
	ScrambleOffset = 1 << 4,
	InitializeCookie = 1 << 5,
	ImportCurrentDirectory = 1 << 6,
	AllocateHigh = 1 << 7,
}




#[derive(Clone)]
pub struct CacheEntry {
	pub hash: u64,
	pub module: u64,
}
#[derive(Clone)]
pub struct LinkEntry {
	pub name_length: u32,
	pub path_length: u32,
	pub data: LDR_DATA_TABLE_ENTRY,
	pub ddag: LDR_DDAG_NODE,
}



#[repr(C)]
#[derive(Clone)]
pub struct State {
	// Base of shared state
	pub base: u64,

	// Function offsets
	pub heavens_gate: u32,
	pub entry: u32,
	pub parse_header: u32,
	pub find_module: u32,
	pub load_module: u32,
	pub map_module: u32,
	pub link_module: u32,
	pub resolve_function: u32,
	pub read_file: u32,

	// Syscall indices
	pub syscall_create_thread: u32,
	pub syscall_virtual_protect: u32,
	pub syscall_virtual_allocate: u32,
	pub syscall_virtual_free: u32,
	pub syscall_open_file: u32,
	pub syscall_read_file: u32,
	pub syscall_query_information: u32,

	pub options: u32,

	pub path_pointer: Option<u64>,


	// Used for recovering stack pointer and releasing thread safely in case of error
	pub recovery: u64,

	// Image base of current image
	pub image: u64,

	// Depth of current recursive subcall
	pub depth: u32,

	// Buffer for file content
	pub file_buffer: Option<u64>,
	pub file_buffer_size: Option<u32>,

	// Pointer to the LdrpHashTable in ntdll
	pub ldrp_hash_table: Option<u64>,
	// Pointer to the LdrpBaseAddressIndex in ntdll
	pub ldrp_index_tree: Option<u64>,

	// Pointer to the top of the debug buffer. None if unused
	pub debug_head: Option<u64>,

	// Loader module cache 
	// Length of the cache in amount of entries
	pub cache_max_length: u32,
	pub cache_length: u32,

	// Link module cache
	// Size of the cache in bytes
	pub link_max_size: u32,
	pub link_size: u32,

	// CacheEntry
	// CacheEntry
	// ...

	// LinkEntry
	// LinkEntry
	// ...
}

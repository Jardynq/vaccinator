#![cfg(windows)]
#![feature(lang_items)]

// Basic dll image for testing

#[allow(non_snake_case)]
#[no_mangle]
extern "system" fn DllMain(_: usize, _: u32, _: *const ()) -> u32 {
	1
}

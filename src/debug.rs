use std::mem::{
	transmute,
	size_of
};
use std::fs::File;

use log::{
	info,
	warn,
	error,

	LevelFilter,
};
use simplelog::{
	TermLogger, WriteLogger, SharedLogger, CombinedLogger,
	Config,
	ColorChoice,
	TerminalMode,
};

use interface::*;




pub fn initialize_logger() {
    let mut log_buffer = String::new();
    let log_level = LevelFilter::max();

	// Initalize terminal logger
    let log_term = TermLogger::new(
        log_level,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    );


	// Initalize file logger
    let log_file_path = "debug.log";
    let log_file = match File::create(log_file_path) {
        Ok(file) => Some(WriteLogger::new(log_level, Config::default(), file)),
        Err(error) => {
            log_buffer.push_str(&format!(
                "failed to open file '{}' for logging: {}",
                log_file_path, error
            ));
            None
        }
    };

	// Combine loggers
    let mut loggers: Vec<Box<dyn SharedLogger>> = vec![log_term];
    if let Some(logger) = log_file {
        loggers.push(logger);
    }

    match CombinedLogger::init(loggers) {
        Ok(_) => (),
        Err(error) => {
            println!("failed to create combined logger: {}", error);
            println!("no further logging will be provided!");
        }
    };

	// Errors have occured during initialization
    if log_buffer.len() > 0 {
        error!("{}", log_buffer);
    }

    info!("logger initialized");
}




const UNIT_SIZE: isize = size_of::<DebugMessage>() as isize;
const INDENT: &'static str = "|    ";

pub fn debug(buffer: Vec<u8>, verbose: bool) {
	let mut result = String::new();

	if buffer.len() >= UNIT_SIZE as usize {
		unsafe {
			let mut pointer = transmute::<_, *const u8>(buffer.as_ptr());
			let max = pointer.offset(buffer.len() as isize);

			match pointer.cast::<DebugMessage>().read() {
				DebugMessage::Call(call) => {
					result.push_str(&debug_call(&mut pointer, call, 0, max, verbose));
				}
				DebugMessage::Null => {
					result.push_str("Debug buffer empty, either the loader was compiled without the 'debug' feature, or loader base wasn't given");
				}
				_ => {
					result.push_str("First message must a call");
				}
			}
		}
	}
	
	info!("\n{}", result);
}


unsafe fn debug_call(pointer: &mut *const u8, call: DebugCall, depth: usize, max: *const u8, verbose: bool) -> String {
	let mut header = String::new();
	let mut body: Vec<String> = Vec::new();
	let mut skip = false;
	*pointer = pointer.offset(UNIT_SIZE);


	let param_count = match call {
		DebugCall::HeavensGate(count) => {
			header.push_str("heavens_gate");
			count
		}
		DebugCall::Entry(count) => {
			header.push_str("entry");
			count
		}
		DebugCall::ParseHeader(count) => {
			skip = true;
			header.push_str("parse_header");
			count
		}
		DebugCall::FindModule(count) => {
			header.push_str("find_module");
			count
		}
		DebugCall::LoadModule(count) => {
			header.push_str("load_module");
			count
		}
		DebugCall::MapModule(count) => {
			header.push_str("map_module");
			count
		}
		DebugCall::LinkModule(count) => {
			header.push_str("link_module");
			count
		}
		DebugCall::ResolveFunction(count) => {
			skip = true;
			header.push_str("resolve_function");
			count
		}
		DebugCall::ReadFile(count) => {
			skip = true;
			header.push_str("read_file");
			count
		}
		
		DebugCall::TlsCallback => {
			header.push_str("tls_callback");
			0
		}
		DebugCall::DllMain => {
			header.push_str("dll_main");
			0
		}

		DebugCall::Null => {
			return format!("");
		}
	} as usize;

	header.push_str("( ");
	header.push_str(&debug_params(pointer, param_count, max));
	header.push_str(" ) ");
	

	while *pointer < max {
		let message = pointer.cast::<DebugMessage>().read();

		match message {
			DebugMessage::Null => {
				if depth != 0 {
					header.push_str("-> !");
				}
				break;
			}
			DebugMessage::Success(count) => {
				header.push_str(&debug_success(pointer, count as usize, max));
				if depth == 0 {
					body.push(format!(":)"));
				}
				break;
			}
			DebugMessage::Failure(reason) => {
				header.push_str(&debug_failure(pointer, reason));
				if depth == 0 {
					body.push(format!(":("));
				}
				break;
			}
			DebugMessage::Call(call) => {
				body.push(debug_call(pointer, call, depth + 1, max, verbose));
				continue;
			}


			DebugMessage::None => {
				body.push(debug_value(pointer, None));
			},
			DebugMessage::Value(value) => {
				body.push(debug_value(pointer, Some(value)));
			},
			DebugMessage::Pointer(address) => {
				body.push(debug_pointer(pointer, address));
			},
			DebugMessage::StringU8(length) => {
				body.push(format!("{}: {}", length, debug_string_u8(pointer, length, max)));
			},
			DebugMessage::StringU16(length) => {
				body.push(format!("{}: {}", length, debug_string_u16(pointer, length, max)));
			},


			DebugMessage::Info(info) => {
				body.push(debug_info(pointer, info));
			},
		}
	}

	if !skip || verbose {
		let mut result = header;
		for part in body {
			let mut smile = true;
			for line in part.lines() {
				smile = false; // :(
				result.push_str(&format!("\n{}{}", INDENT, line));
			}
			if smile {
				result.push_str(&format!("\n{}:)", INDENT));
			}
		}
		result
	} else {
		String::new()
	}
}

unsafe fn debug_success(pointer: &mut *const u8, count: usize, max: *const u8) -> String {
	let mut result = String::new();
	*pointer = pointer.offset(UNIT_SIZE);

	result.push_str("-> ");
	if count > 1 {
		result.push_str("( ");
	}
	if count == 0 {
		result.push_str(":)");
	} else {
		result.push_str(&debug_params(pointer, count, max));
	}
	if count > 1 {
		result.push_str(" )");
	}

	result
}
unsafe fn debug_info(pointer: &mut *const u8, info: DebugInfo) -> String {
	let mut result = String::new();
	*pointer = pointer.offset(UNIT_SIZE);

	// TODO: fine messages pls
	match info {
		DebugInfo::MappingSuccessful => {
			result.push_str(":)");
		}
		info => {
			result.push_str("Info: ");
			result.push_str(&format!("{:x?}", info));
		}
	}

	result
}
unsafe fn debug_failure(pointer: &mut *const u8, reason: DebugFailure) -> String {
	let mut result = String::new();
	*pointer = pointer.offset(UNIT_SIZE);

	result.push_str("-> ! ");
	// TODO: fine messages pls
	match reason {
		_ => {
			result.push_str(&format!("{:x?}", reason))
		}
	}

	result
}


unsafe fn debug_params(pointer: &mut *const u8, count: usize, max: *const u8) -> String {
	let mut result = String::new();

	for index in 0..count {
		if *pointer >= max {
			break;
		}

		match pointer.cast::<DebugMessage>().read() {
			DebugMessage::None => {
				result.push_str(&debug_value(pointer, None));
			}
			DebugMessage::Value(value) => {
				result.push_str(&debug_value(pointer, Some(value)));
			}
			DebugMessage::StringU8(length) => {
				result.push_str(&debug_string_u8(pointer, length, max));
			}
			DebugMessage::StringU16(length) => {
				result.push_str(&debug_string_u16(pointer, length, max));
			}

			_ => {
				*pointer = pointer.offset(UNIT_SIZE);
				result.push_str("( ! )");
			}
		}

		if index < (count - 1) {
			result.push_str(", ");
		}
	}

	result
}


unsafe fn debug_value(pointer: &mut *const u8, value: Option<u64>) -> String {
	*pointer = pointer.offset(UNIT_SIZE);
	match value {
		Some(value) => format!("{:x}", value),
		None => format!("None"),
	}
}
unsafe fn debug_pointer(pointer: &mut *const u8, address: u64) -> String {
	*pointer = pointer.offset(UNIT_SIZE);
	format!("-> {:x}", address)
}
unsafe fn debug_string_u8(pointer: &mut *const u8, length: u64, max: *const u8) -> String {
	let mut result = String::new();
	*pointer = pointer.offset(UNIT_SIZE);

	let mut bytes = vec![];
	for index in 0..length {
		let pointer = pointer.offset(index as isize);
		if pointer >= max {
			break;
		}

		let value = pointer.read();
		if value != 0 {
			bytes.push(value);
		}
	}
	
	*pointer = pointer.offset(length as isize);
	let string = String::from_utf8(bytes).unwrap_or(format!("( ? )"));
	result.push_str(&string);
	result
}
unsafe fn debug_string_u16(pointer: &mut *const u8, length: u64, max: *const u8) -> String {
	debug_string_u8(pointer, length * 2, max)
}

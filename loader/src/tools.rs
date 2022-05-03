#[allow(unused_macros)]
#[allow(unused_variables)]
#[allow(unused_assignments)]




/**
	Calculates the sdbm or x65599 hash of a string
	This is what windows uses, so we can use it to add entries to the ldrp hash table
	we also use it for our own hash table
*/
#[macro_export]
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
		while true $( && _count < ($($length)*) as usize )? $( $( && string.read() != (($($end)*) as _) )* )? {
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


/**
	it's memcpy, you know what it does
*/
#[macro_export] 
macro_rules! memcpy {
	( StringU8 = $( $dst:expr )* , StringU8 = $( $src:expr )*, $($pass:tt)* ) => {
		memcpy!( $( $dst )* as *mut u8, $( $src )* as *const u8, $($pass)* )
	};
	( StringU8 = $( $dst:expr )* , StringU16 = $( $src:expr )*, $($pass:tt)* ) => {
		memcpy!( $( $dst )* as *mut u8, $( $src )* as *const u16, $($pass)* )
	};
	( StringU16 = $( $dst:expr )* , StringU8 = $( $src:expr )*, $($pass:tt)* ) => {
		memcpy!( $( $dst )* as *mut u16, $( $src )* as *const u8, $($pass)* )
	};
	( StringU16 = $( $dst:expr )* , StringU16 = $( $src:expr )*, $($pass:tt)* ) => {
		memcpy!( $( $dst )* as *mut u16, $( $src )* as *const u16, $($pass)* )
	};
	( String = $( $dst:expr )* , String = $( $src:expr )* , $($pass:tt)* ) => {{
		match $( $dst )* {
			::interface::CString::U8(dst) => match $( $src )* {
				::interface::CString::U8(src) => {
					memcpy!(StringU8 = dst, StringU8 = src, $($pass)* )
				}
				::interface::CString::U16(src) => {
					memcpy!(StringU8 = dst, StringU16 = src, $($pass)* )
				}
			}
			::interface::CString::U16(dst) => match $( $src )* {
				::interface::CString::U8(src) => {
					memcpy!(StringU16 = dst, StringU8 = src, $($pass)* )
				}
				::interface::CString::U16(src) => {
					memcpy!(StringU16 = dst, StringU16 = src, $($pass)* )
				}
			}
		}
	}};
	( $( $dst:expr )* , $( $src:expr )* $(, Length = $( $length:expr )* )? $(, Token[ $( $( $end:expr )* ),* ] )? ) => {{
		let mut dst = $( $dst )*;
		let mut src = $( $src )*;

		let mut _count = 0;
		while true $( && _count < ($($length)*) as usize)? $( $( && src.read() != (($($end)*) as _) )* )? {
			dst.write(src.read() as _);
			dst = dst.offset(1);
			src = src.offset(1);
			_count += 1;
		}
		_count
	}};
}


/**
	get's length of string, yup
*/
#[macro_export] 
macro_rules! string_len {
	( StringU8 = $( $string:expr )* , $($pass:tt)* ) => {
		string_len!( $( $string )* as *const u8, $($pass)* )
	};
	( StringU16 = $( $string:expr )* , $($pass:tt)* ) => {
		string_len!( $( $string )* as *const u16, $($pass)* )
	};
	( String = $( $string:expr )* , $($pass:tt)* ) => {{
		match $( $string )* {
			::interface::CString::U8(string) => {
				string_len!(StringU8 = string, $($pass)* )
			}
			::interface::CString::U16(string) => {
				string_len!(StringU16 = string, $($pass)* )
			}
		}
	}};
	( $( $string:expr )* $(, Length = $( $length:expr )* )? , Token[ $( $( $end:expr )* ),* ] ) => {{
		let string = $( $string )*;
		if !string.is_null() {
			let mut length = 0;
			while true $( && string.offset(length as isize).read() != (($($end)*) as _) )* {
				length += 1;
			}
			length as usize
		} else {
			0
		}
	}};
}




#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Strcmp {
	Equal,
	LeftGreater,
	LeftLonger,
	RightGreater,
	RightLonger,
}
#[macro_export] 
macro_rules! string_cmp {
	( StringU8 = $( $lhs:expr )* , StringU8 = $( $rhs:expr )*, $($pass:tt)* ) => {
		string_cmp!( $( $lhs )* as *mut u8, $( $rhs )* as *const u8, $($pass)* )
	};
	( StringU8 = $( $lhs:expr )* , StringU16 = $( $rhs:expr )*, $($pass:tt)* ) => {
		string_cmp!( $( $lhs )* as *mut u8, $( $rhs )* as *const u16, $($pass)* )
	};
	( StringU16 = $( $lhs:expr )* , StringU8 = $( $rhs:expr )*, $($pass:tt)* ) => {
		string_cmp!( $( $lhs )* as *mut u16, $( $rhs )* as *const u8, $($pass)* )
	};
	( StringU16 = $( $lhs:expr )* , StringU16 = $( $rhs:expr )*, $($pass:tt)* ) => {
		string_cmp!( $( $lhs )* as *mut u16, $( $rhs )* as *const u16, $($pass)* )
	};
	( String = $( $lhs:expr )* , String = $( $rhs:expr )* , $($pass:tt)* ) => {{
		match $( $lhs )* {
			::interface::CString::U8(lhs) => match $( $rhs )* {
				::interface::CString::U8(rhs) => {
					string_cmp!(StringU8 = lhs, StringU8 = rhs, $($pass)* )
				}
				::interface::CString::U16(rhs) => {
					string_cmp!(StringU8 = lhs, StringU16 = rhs, $($pass)* )
				}
			}
			::interface::CString::U16(lhs) => match $( $rhs )* {
				::interface::CString::U8(rhs) => {
					string_cmp!(StringU16 = lhs, StringU8 = rhs, $($pass)* )
				}
				::interface::CString::U16(rhs) => {
					string_cmp!(StringU16 = lhs, StringU16 = rhs, $($pass)* )
				}
			}
		}
	}};
	( $( $lhs:expr )* , $( $rhs:expr )* , $( $ignore:expr )*  $(, Length = $( $length:expr )* )? $(, Token[ $( $( $end:expr )* ),* ] )? ) => {{
		let mut lhs = $( $lhs )*;
		let mut rhs = $( $rhs )*;

		let mut calculated = false;
		let mut lhs_length = 0;
		let mut rhs_length = 0;
		$(
			lhs_length = string_len!(lhs, Token[ $( $( $end )* ),* ]);
			calculated = true;
		)?
		$(
			rhs_length = string_len!(rhs, Token[ $( $( $end )* ),* ]);
			calculated = true;
		)?
		let length = if calculated {
			lhs_length.min(rhs_length) $( .min( $( $length )* as usize ) )?
		} else {
			0 $( + $( $length )* as usize )?
		};

		let mut lhs_char = 0;
		let mut rhs_char = 0;
		let mut count = 0;
		while lhs_char == rhs_char && count < length {
			lhs_char = lhs.read() as _;
			rhs_char = rhs.read() as _;
			if $($ignore)* {
				if lhs_char <= 'Z' as _ && lhs_char >= 'A' as _ {
					lhs_char += 0x20
				} 
				if rhs_char <= 'Z' as _ && rhs_char >= 'A' as _ {
					rhs_char += 0x20
				}
			}

			lhs = lhs.offset(1);
			rhs = rhs.offset(1);
			count += 1;
		}

		let diff = lhs_char as i32 - rhs_char as i32;
		if diff > 0 { Strcmp::LeftGreater } 
		else if diff < 0 { Strcmp::RightGreater }
		else {
			if lhs_length > rhs_length { Strcmp::LeftLonger }
			else if lhs_length < rhs_length { Strcmp::RightLonger }
			else { Strcmp::Equal }
		}
	}};
}
#[macro_export] 
macro_rules! string_eq {
	( $( $pass:tt )* ) => {{
		let status = string_cmp!( $( $pass )* );
		status == Strcmp::Equal || status == Strcmp::LeftLonger  || status == Strcmp::RightLonger 
	}};
}



#[macro_export] 
macro_rules! callable {
	( $( $func:expr )* ) => {
		::core::mem::transmute(($($func)*) as usize)
	};
	( $( $base:expr )* , $( $offset:expr )* ) => {
		::core::mem::transmute(($($base)*) as usize + ($($offset)*) as usize)
	};
}

#[macro_export] 
macro_rules! flag {
	($( $value:expr )*, $( $flag:expr )*) => {
		// Check if flag is set
		(($($value)*) as u64 & ($($flag)*) as u64) != 0
	};
	($( $value:expr )*, $( $flag:expr )*, $( $state:expr )*) => {
		// Set flag
		if ($($state)*) as bool {
			($($value)*) as u64 | ($($flag)*) as u64
		} else {
			($($value)*) as u64 & !(($($flag)*) as u64)
		}
	}
}

#[macro_export]
macro_rules! ntstatus_valid {
	( $( $status:expr )* ) => {
		// STATUS_PORT_NOT_SET sometimes gets returned when a debugger is attached
		// though the value expected from the syscall is fine.
		($( $status )*) == 0 || (($( $status )*) & 0xffff_ffff) as i32 == ::winapi::shared::ntstatus::STATUS_PORT_NOT_SET 
	}
}




#[macro_export]
macro_rules! push_cache {
	( $( $state:expr )*, $($hash:expr)*, $($module:expr)*) => {{
		let state: &mut ::interface::State = $( $state )*;
		let cache = (state as *mut State).offset(1).cast::<CacheEntry>();

		if state.cache_length + 1 >= state.cache_max_length {
			false
		} else {
			cache.offset(state.cache_length as isize).write(CacheEntry {
				hash: $($hash)* as _,
				module: $($module)* as _,
			});
			state.cache_length += 1;
			true
		}
	}};
}


#[macro_export]
macro_rules! recover {
	(  ) => {{
		// Reset thread stack and registers and return execution to after entry
		// Used for letting go after hijack, or early return after fatal eror
	}};
}
#[macro_export]
macro_rules! fatal {
	(  ) => {{
		// No way back type of fatal, terminate thread using syscall
		::nt_syscall::syscall!(

		)
	}};
}




// Small wrapper to ensure some compiler warnings even with debug disabled
#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! debug_internal {
	( $( $token:tt )* ) => {
		// Do nothing
	};
}
#[cfg(feature = "debug")]
#[macro_export]
macro_rules! debug_internal {
	( $( $token:tt )* ) => {
		$( $token )*
	};
}

#[macro_export]
macro_rules! break_debug {
	() => { debug_internal! {
		asm!(
			"int 3"
		)
	}};
}

#[macro_export]
macro_rules! write_debug {
	( $( $state:expr )*, Type = $($debug:tt)* ) => { debug_internal! {
		let state: &mut ::interface::State = ($( $state )*);
		if let Some(head) = state.debug_head.as_mut() {
			let ptr = *head as *mut ::interface::DebugMessage;
			ptr.write(::interface::DebugMessage::$($debug)*);
			*head += ::interface::DEBUG_SIZE as u64; 
		}
	}};
	( $( $state:expr )*, $($debug:ident)* = Option = $($value:expr)* $(, $($pass:tt)* )?) => { debug_internal! {
		let value = $($value)*;
		match value {
			Some(value) => {
				write_debug!( $( $state )*, $( $debug )* = value $(, $($pass)* )?);
			}
			None => {
				write_debug!( $( $state )*, Value = None);
			}
		};
	}};



	
	( $( $state:expr )*, Call = $($call:tt)* ) => { debug_internal! {
		write_debug!( $( $state )*, Type = Call(::interface::DebugCall::$($call)*));
	}};
	( $( $state:expr )*, Success = $($count:tt)* ) => { debug_internal! {
		write_debug!( $( $state )*, Type = Success($($count)* as u64));
	}};
	( $( $state:expr )*, Info = $($info:tt)* ) => { debug_internal! {
		write_debug!( $( $state )*, Type = Info(::interface::DebugInfo::$($info)*));
	}};
	( $( $state:expr )*, Failure = $($failure:tt)* ) => { debug_internal! {
		write_debug!( $( $state )*, Type = Failure(::interface::DebugFailure::$($failure)*));
	}};




	( $( $state:expr )*, Value = None ) => { debug_internal! {
		write_debug!( $( $state )*, Type = None);
	}};
	( $( $state:expr )*, Value = $($value:tt)* ) => { debug_internal! {
		write_debug!( $( $state )*, Type = Value( $($value)* as u64));
	}};
	( $( $state:expr )*, Pointer = $($value:tt)* ) => { debug_internal! {
		write_debug!( $( $state )*, Type = Pointer( ::core::mem::transmute::<_, usize>($($value)*) as u64));
	}};



	( $( $state:expr )*, String = $($string:expr)*, $($pass:tt)* ) => { debug_internal! {
		match $($string)* {
			interface::CString::U8(ptr) => {
				write_debug!($( $state)*, StringU8 = ptr, $($pass)* );
			}
			interface::CString::U16(ptr) => {
				write_debug!($( $state)*, StringU16 = ptr, $($pass)* );
			}
		};
	}};
	( $( $state:expr )*, StringU8 = $($string:expr)*, $($pass:tt)* ) => { debug_internal! {
		let state: &mut interface::State = ($( $state )*);

		let mut length = 0;
		if let Some(head) = state.debug_head {
			let string = $($string)* as *const u8;
			let buffer = (head as usize + ::interface::DEBUG_SIZE) as *mut u8;
			length = memcpy!(buffer, string, $($pass)* ) as u64;

			write_debug!(state, Type = StringU8(length));
		}
		if let Some(head) = state.debug_head.as_mut() {
			*head += length;
		}
	}};
	( $( $state:expr )*, StringU16 = $($string:expr)*, $($pass:tt)* ) => { debug_internal! {
		let state: &mut ::interface::State = ($( $state )*);

		let mut length = 0;
		if let Some(head) = state.debug_head {
			let string = $($string)* as *const u16;
			let buffer = (head as usize + ::interface::DEBUG_SIZE) as *mut u16;
			length = memcpy!(buffer, string, $($pass)* ) as u64;

			write_debug!(state, Type = StringU16(length));
		}
		if let Some(head) = state.debug_head.as_mut() {
			*head += length * 2;
		}
	}};
}

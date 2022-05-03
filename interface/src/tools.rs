#[macro_export]
macro_rules! write_debug2 {
	( $( $state:expr )*, Type = $($debug:tt)* ) => {{
		let state: &mut ::interface::State = ($( $state )*);

		let ptr = ::core::mem::transmute::<_, *mut ::interface::DebugMessage>(state.debug_head as usize);
		ptr.write(::interface::DebugMessage::$($debug)*);
		
		state.debug_head += ::core::mem::size_of::<interface::DebugMessage>() as u64; 
	}};




	( $( $state:expr )*, Call = $($call:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = Debug$($call)*::Call);
	}};
	( $( $state:expr )*, Return ) => {{
		::interface::write_debug!( $( $state )*, Type = Return);
	}};
	( $( $state:expr )*, Success = $($value:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = Success( $($value)*  as u64));
	}};
	( $( $state:expr )*, ParamStart ) => {{
		::interface::write_debug!( $( $state )*, Type = ParamStart);
	}};
	( $( $state:expr )*, ParamEnd ) => {{
		::interface::write_debug!( $( $state )*, Type = ParamEnd);
	}};


	( $( $state:expr )*, Value = $($value:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = Value($($value)* as u64));
	}};
	( $( $state:expr )*, Some ) => {{
		::interface::write_debug!( $( $state )*, Type = Some);
	}};
	( $( $state:expr )*, None ) => {{
		::interface::write_debug!( $( $state )*, Type = None);
	}};


	( $( $state:expr )*, String = $($string:expr)*, $( $($pass:tt)* ),* ) => {{
		let length = match  $($string)* {
			interface::CString::U8(ptr) => {
				::interface::write_debug!($( $state)*, StringU8 = ptr, $( $($pass)* ),* );
			}
			interface::CString::U16(ptr) => {
				::interface::write_debug!($( $state)*, StringU16 = ptr, $( $($pass)* ),* );
			}
		};
	}};
	( $( $state:expr )*, StringU8 = $($string:expr)*, $( $($pass:tt)* ),* ) => {{
		let state: &mut interface::State = ($( $state )*);
		let offset = ::core::mem::size_of::<interface::DebugMessage>();

		let string = $($string)* as *const u8;
		let buffer = ::core::mem::transmute::<_, *mut u8>(state.debug_head as usize + offset);
		let length = ::interface::memcpy!(buffer, string, $( $($pass)* ),* ) as u64;

		::interface::write_debug!(state, Type = StringU8(length as u32));
		state.debug_head += length;
	}};
	( $( $state:expr )*, StringU16 = $($string:expr)*, $( $($pass:tt)* ),* ) => {{
		let state: &mut ::interface::State = ($( $state )*);
		let offset = ::core::mem::size_of::<interface::DebugMessage>();

		let string = $($string)* as *const u16;
		let buffer = ::core::mem::transmute::<_, *mut u16>(state.debug_head as usize + offset);
		let length = ::interface::memcpy!(buffer, string, $( $($pass)* ),* ) as u64;

		::interface::write_debug!(state, Type = StringU16(length as u32));
		state.debug_head += length * 2;
	}};


	( $( $state:expr )*, HeavensGate = $($param:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = HeavensGate(::interface::DebugHeavensGate::$($param)*));
	}};
	( $( $state:expr )*, Entry = $($param:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = Entry(::interface::DebugEntry::$($param)*));
	}};
	( $( $state:expr )*, ParseHeader = $($param:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = ParseHeader(::interface::DebugParseHeader::$($param)*));
	}};
	( $( $state:expr )*, FindModule = $($param:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = FindModule(::interface::DebugFindModule::$($param)*));
	}};
	( $( $state:expr )*, LoadModule = $($param:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = LoadModule(::interface::DebugLoadModule::$($param)*));
	}};
	( $( $state:expr )*, MapModule = $($param:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = MapModule(::interface::DebugMapModule::$($param)*));
	}};
	( $( $state:expr )*, ResolveFunction = $($param:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = ResolveFunction(::interface::DebugResolveFunction::$($param)*));
	}};
	( $( $state:expr )*, ReadFile = $($param:tt)* ) => {{
		::interface::write_debug!( $( $state )*, Type = ReadFile(::interface::DebugReadFile::$($param)*));
	}};
}












#[macro_export] 
macro_rules! memcpy {
	( $( $dst:expr )* , $( $src:expr )* $(, Length = $( $length:expr )* )? $(, Token[ $( $( $end:expr )* ),* ] )? ) => {{
		let mut dst = $( $dst )*;
		let mut src = $( $src )*;

		let mut _count = 0;
		while true $( && _count < ($($length)*) )? $( $( && src.read() != (($($end)*) as _) )* )? {
			dst.write(src.read() as _);
			dst = dst.offset(1);
			src = src.offset(1);
			_count += 1;
		}
		_count as usize
	}}
}
#[macro_export] 
macro_rules! strlen {
	( $( $string:expr )* , Token[ $( $( $end:expr )* ),* ] ) => {{
		let string = $( $string )*;
		let mut length = 0;
		while true $( && string.offset(length).read() != (($($end)*) as _) )* {
			length += 1;
		}
		length as usize
	}}
}
#[macro_export] 
macro_rules! strcmp {
	( $( $lhs:expr )* , $( $rhs:expr )* $(, IgnoreCase = $( $lowercase:expr )* )? $(, Length = $( $length:expr )* )? $(, Token[ $( $( $end:expr )* ),* ] )? ) => {{
		let mut lhs = $( $lhs )*;
		let mut rhs = $( $rhs )*;

		let mut _count = 0;
		let mut is_equal = true;
		let mut lhs_char;
		let mut rhs_char;
		while is_equal $( && _count < ($($length)*) )? $( $( && lhs.read() != (($($end)*) as _) )* $( && rhs.read() != (($($end)*) as _) )* )? {
			lhs_char = lhs.read();
			rhs_char = rhs.read();
			$(
				if $($lowercase)* {
					if lhs_char <= 'Z' as _ && lhs_char >= 'A' as _ {
						lhs_char += 0x20
					} 
					if rhs_char <= 'Z' as _ && rhs_char >= 'A' as _ {
						rhs_char += 0x20
					} 
				}
			)?

			is_equal &= lhs_char == rhs_char as _;
			lhs = lhs.offset(1);
			rhs = rhs.offset(1);
			_count += 1;
		}

		$(
			is_equal &= false $( || lhs.read() == (($($end)*) as _) )*;
			is_equal &= false $( || rhs.read() == (($($end)*) as _) )*;
		)?

		is_equal
	}}
}


#[macro_export] 
macro_rules! flag {
	($( $value:expr )*, $( $flag:expr )*) => {
		(($($value)*) as u64 & ($($flag)*) as u64) != 0
	};
	($( $value:expr )*, $( $flag:expr )*, $( $state:expr )*) => {
		if ($($state)*) != 0 {
			($($value)*) as u64 | ($($flag)*) as u64
		} else {
			($($value)*) as u64& !(($($flag)*) as u64) 
		}
	}
}



#[macro_export] 
macro_rules! process_parameters {
	() => { unsafe {
		::core::mem::transmute::<_, &mut ::ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS>(::nt_syscall::peb!().ProcessParameters)
	}}
}

#[macro_export] 
macro_rules! kuser_shared_data {
	() => { unsafe {
		::core::mem::transmute::<_, &mut ::ntapi::ntexapi::KUSER_SHARED_DATA>(0x7ffe0000 as usize)
	}}
}



#[macro_export] 
macro_rules! timestamp {
	() => { unsafe {
		let mut timestamp_lo: u32;
		let mut timestamp_hi: u32;
		asm!(
			"rdtsc",
			out("eax") timestamp_lo,
			out("edx") timestamp_hi
		);
		timestamp_lo as u64 + ((timestamp_hi as u64) << 0x20)
	}}
}

#[macro_export] 
macro_rules! cpuid {
	( $( $index:expr )* ) => {{
		let mut a: u32 = 0;
		let mut b: u32 = 0;
		let mut c: u32 = 0;
		let mut d: u32 = 0;

		asm!(
			"cpuid",
			"mov esi, ebx",

			in("eax") ($($index)*) as u32,
			
			lateout("eax") a,
			lateout("esi") b,
			lateout("ecx") c,
			lateout("edx") d,
		);

		(a, b, c, d)
	}}
}

#[macro_export] 
#[cfg(target_arch = "x86_64")]
macro_rules! rdrand {
	() => {
		rdrand!(0x100)
	};
	( $( $shots:expr )* ) => { unsafe {
		let mut value: u64 = 0;
		
		let (_, _, c, _) = ::interface::cpuid!(1);
		if ::interface::flag!(c, 1 << 30) {
			for _ in 0..( $( $shots )* ) {
				asm!(
					"rdrand rax",
					out("rax") value,
				);
				if value != 0 {
					break;
				}
			}
		}

		if value == 0 {
			::interface::timestamp!() as u64
		} else {
			value
		}
	}};
}

#[macro_export] 
#[cfg(target_arch = "x86")]
macro_rules! rdrand {
	() => {
		rdrand!(0x100)
	};
	( $( $shots:expr )* ) => { unsafe {
		let mut value_hi: u32 = 0;
		let mut value_lo: u32 = 0;

		let (_, _, c, _) = ::interface::cpuid!(1);
		if ::interface::flag!(c, 1 << 30) {
			for _ in 0..( $( $shots )* ) {
				if value_hi == 0 {
					asm!(
						"rdrand eax",
						out("eax") value_hi,
					);
				}
				if value_lo == 0 {
					asm!(
						"rdrand eax",
						out("eax") value_lo,
					);
				}
				if value_hi != 0 && value_lo != 0 {
					break;
				}
			}
		}

		if value_lo == 0 || value_hi == 0 {
			::interface::timestamp!()
		} else {
			value_lo as u64 + ((value_hi as u64) << 0x20)
		}
	}};
}


pub const DEBUG_SIZE: usize = ::core::mem::size_of::<DebugMessage>();





// new design
/**

	have an enum for every function and be very verbose about them.

	failure rename to error, and give it a count instead like success, 
	then the infos/ values that come after vil be pretty printet

*/


#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DebugMessage {
	Null,

	None,
	//Params(u64),
	Value(u64),
	Pointer(u64),
	StringU8(u64),
	StringU16(u64),


	// Use this to create an indented block:
	// fn( a , b, c ) -> d
	// 		DoingA
	// 		{	BlockThiny
	//			DoingD
	//		}
	//BlockStart,
	//BlockEnd,

	// Struct - kinde like block but with members, make a nice macro for it

	Call(DebugCall),

	Success(u64),
	Info(DebugInfo),
	Failure(DebugFailure),
}
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DebugInfo {
	Null,

	Relocating,
	ResolvingImports,
	ImportForwarded,
	Exectuting,

	ImageIsDynamicBase,
	MappingImage,
	MappingSuccessful,

	ImageFoundInCache,
	ImageFoundInApi,
	ImageFoundInPeb,
	ImageFoundInDisk,
	ImageIsApi,

	ImageFoundInSystemRoot,
	ImageFoundInWindir,
	ImageFoundInEnvironmentPath,
	ImageNotInSystemRoot,
	ImageNotInWindir,
	ImageNotInEnvironmentPath,

	CouldNotFindLdrpHashTable,
	FoundLdrpHashTable(u64),
	FailedToCache,
	SearchingForLdrpHashTable,
	SearchingForLdrpAddressIndex,
	RootIsNotBlack,
	FoundLdrpIndexTree(u64),
	InsertedIntoLinkedList,
	InsertedIntoIndexTree,
	InsertedIntoHashTable,
	CouldNotFindLdrpIndexTree,

	FailedToDeallocateBuffer(u32),
}
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DebugFailure {
	Null,

	CpuModeInvalid(u16),

	FailedToOpenFile(u32),
	FailedToGetFileSize(u32),
	FailedToAllocateBuffer(u32),
	FailedToReadFile(u32),

	NotFound,
	NoImage,
	InvalidBuffer,
	BufferTooSmall,
	InvalidModule,
	InvalidDosHeader,
	InvalidNtHeader,
	InvalidHeader,
	InvalidExports,
	InvalidMagic(u16),
	InvalidMachine(u16),
	CacheLimitReached,
	LinkLimitReached,
}
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DebugCall {
	Null,

	HeavensGate(u64),
	Entry(u64),	
	ParseHeader(u64),
	FindModule(u64),
	LoadModule(u64),
	MapModule(u64),
	LinkModule(u64),
	ResolveFunction(u64),
	ReadFile(u64),

	TlsCallback,
	DllMain,
}

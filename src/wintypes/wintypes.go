package wintypes

import "golang.org/x/sys/windows"

const (
	genericRead         = 0x80000000
	genericWrite        = 0x40000000
	openExisting        = 3
	fileAttributeNormal = 0x80
	invalidHandleValue  = ^windows.Handle(0)
	imageDosSignature   = 0x5a4d
	imageNtHeaders      = 0x00004550
)

type ImageDosHeader struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

const (
	imageSizeofFileHeader = 20

	imageFileRelocsStripped       = 0x0001
	imageFileExecutableImage      = 0x0002
	imageFileLineNumsStripped     = 0x0004
	imageFileLocalSymsStripped    = 0x0008
	imageFileAggresiveWSTrim      = 0x0010
	imageFileLargeAddressAware    = 0x0020
	imageFileBytesReversedLo      = 0x0080
	imageFile32BitMachine         = 0x0100
	imageFileDebugStripped        = 0x0200
	imageFileRemovableRunFromSwap = 0x0400
	imageFileNetRunFromSwap       = 0x0800
	imageFileSystem               = 0x1000
	imageFileDLL                  = 0x2000
	imageFileUpSystemOnly         = 0x4000
	imageFileBytesReversedHi      = 0x8000
	imageFileMachineUnknown       = 0
	imageFileMachineI386          = 0x014c
	imageFileMachineAMD64         = 0x8664
)

type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

const (
	imageNTOptionalHdr32Magic     = 0x10b
	imageNTOptionalHdr64Magic     = 0x20b
	imageNumberofDirectoryEntries = 16
)

// 64-Bit Image Optional Header
type ImageOptionalHeader struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [imageNumberofDirectoryEntries]ImageDataDirectory
}

const imageSizeofShortName = 8

type ImageSectionHeader struct {
	Name                 [8]byte
	Misc                 uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

const (
	imageScnMEMWrite      = 0x80000000
	imageScnCNTCode       = 0x00000020
	imageScnCNTUninitData = 0x00000080
	imageScnMEMExecute    = 0x20000000
	imageScnCNTInitData   = 0x00000040
	imageScnMEMRead       = 0x40000000
	fileBegin             = 0
)

type union struct {
	PhysicalAddress uint32
	VirtualSize     uint32
}

const imageSizeofSectionHeader = 40

type ImageNtHeaders struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader
}

type PImageNtHeaders64 *ImageNtHeaders

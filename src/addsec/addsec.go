package addsec

import (
	"encoding/binary"
	"log"
	"os"
	"unsafe"

	"github.com/joshfinly/addsec/src/wintypes"
	"github.com/saferwall/pe"
)

func align(size, align, addr uint32) uint32 {
	if size%align == 0 {
		return addr + size
	}
	return addr + (size/align+1)*align
}

func AddSection(filepath string, newSecSize uint32, newSecData []byte) error {

	file, err := os.OpenFile(filepath, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// read the DOS header
	dosHeader := wintypes.ImageDosHeader{}
	err = binary.Read(file, binary.LittleEndian, &dosHeader)
	if err != nil {
		log.Fatal(err)
	}

	// seek to the start of the NT headers
	_, err = file.Seek(int64(dosHeader.E_lfanew), 0)
	if err != nil {
		log.Fatal(err)
	}

	// read the NT headers
	ntHeaders := wintypes.ImageNtHeaders{}
	err = binary.Read(file, binary.LittleEndian, &ntHeaders)
	if err != nil {
		log.Fatal(err)
	}

	optHeader := wintypes.ImageOptionalHeader{}

	// calculate the start offset of the section headers table
	sectionTableOffset := uint32(dosHeader.E_lfanew) +
		uint32(binary.Size(ntHeaders.Signature)) +
		uint32(binary.Size(ntHeaders.FileHeader)) +
		uint32(binary.Size(optHeader))

	fileHeaderoffset := dosHeader.E_lfanew + 4
	// Seek to the file header offset
	_, err = file.Seek(int64(fileHeaderoffset), 0)
	if err != nil {
		log.Fatal(err)
	}

	// Read the file header
	fileHeader := wintypes.ImageFileHeader{}
	err = binary.Read(file, binary.LittleEndian, &fileHeader)
	if err != nil {
		log.Fatal(err)
	}

	//fileHeader.NumberOfSections += 1

	// Seek to the file header offset
	_, err = file.Seek(int64(fileHeaderoffset), 0)
	if err != nil {
		log.Fatal(err)
	}

	// Write the updated file header
	err = binary.Write(file, binary.LittleEndian, fileHeader)
	if err != nil {
		log.Fatal(err)
	}

	// Seek to the optional header
	optHeaderOffset := int(dosHeader.E_lfanew) + 4 + int(unsafe.Sizeof(fileHeader))
	_, err = file.Seek(int64(optHeaderOffset), 0)
	if err != nil {
		log.Fatal(err)
	}

	// Read the optional header
	err = binary.Read(file, binary.LittleEndian, &optHeader)
	if err != nil {
		log.Fatal(err)
	}

	// Seek back to the start of the section table in the file
	_, err = file.Seek(int64(sectionTableOffset), 0)
	if err != nil {
		log.Fatal(err)
	}

	// Create an empty section header (use for size now, for our new section later)
	sectionHeader := wintypes.ImageSectionHeader{}

	// Read the existing section headers
	sectionHeaders := make([]wintypes.ImageSectionHeader, int(ntHeaders.FileHeader.NumberOfSections)-1)
	err = binary.Read(file, binary.LittleEndian, sectionHeaders)
	if err != nil {
		log.Fatal(err)
	}

	// Get last header to work new section off of
	lastSec := sectionHeaders[len(sectionHeaders)-1]

	// Create a random string of characters for the section name
	sectName := [8]byte{'.', 'm', 't', 'd', 'a', 0x00}
	// Populate the new section header
	sectionHeader = wintypes.ImageSectionHeader{
		Name:                 sectName,
		Misc:                 align(newSecSize, optHeader.SectionAlignment, 0),
		VirtualAddress:       align(lastSec.Misc, optHeader.SectionAlignment, lastSec.VirtualAddress),
		SizeOfRawData:        align(newSecSize, optHeader.FileAlignment, 0),
		PointerToRawData:     align(lastSec.SizeOfRawData, optHeader.FileAlignment, lastSec.PointerToRawData),
		PointerToRelocations: 0,
		PointerToLinenumbers: 0,
		NumberOfRelocations:  0,
		NumberOfLinenumbers:  0,
		Characteristics:      pe.ImageScnMemExecute | pe.ImageScnMemRead,
	}

	// Append the new section header to the list of existing headers
	sectionHeaders = append(sectionHeaders, sectionHeader)

	// Seek back to the start of the section table in the file
	_, err = file.Seek(int64(sectionTableOffset), 0)
	if err != nil {
		log.Fatal(err)
	}

	err = binary.Write(file, binary.LittleEndian, sectionHeaders)
	if err != nil {
		log.Fatal(err)
	}

	// Seek to the end of the file
	file.Seek(int64(sectionHeader.PointerToRawData), 0)
	err = binary.Write(file, binary.LittleEndian, newSecData)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

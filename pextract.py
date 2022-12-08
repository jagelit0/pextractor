import pefile
import peutils
import hashlib
import argparse
import math

def banner():
    print("""
    ==========================
    |       PExtractor       |
    ==========================
    """)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", type=str, help="Select PE file to scan")
    parser.add_argument("-s", "--sections", action='store_true', help="Extract sections")
    parser.add_argument("-i", "--imports", action='store_true', help="Extract imported DLLs")
    parser.add_argument("-e", "--exports", action='store_true', help="Extract exported Symbols")
    parser.add_argument("-x", "--extract-all", action='store_true', help="Extract all Headers")
    parser.add_argument("-dh", "--dos-header", action='store_true', help="Extract DOS Header")
    parser.add_argument("-nh", "--nt-header", action='store_true', help="Extract File Header")
    parser.add_argument("-vt", "--virus-total", action='store_true', help="Search hash in VirusTotal")

    args = parser.parse_args()

    targetFile = args.target
    
    if not targetFile:
        print("[!] No file selected.")
        exit(1)
    else:
        try:
            banner()

            pe = pefile.PE(targetFile)
            vTotal = args.virus_total

            extractHash(targetFile, vTotal)
            print("\n [+] Filename:", targetFile)

            extractArch(pe)

            # Extract entropy
            with open(targetFile, "rb") as f:
                data = f.read()

            entropy = extracEntropy(data)
            if entropy < 7.40000:
                print(" [+] Entropy:", round(entropy, 5), "Not packed")
            else:
                # Detect possible packer
                signatures = peutils.SignatureDatabase('peid_signatures/userdb.txt')
                matches = signatures.match(pe, ep_only = True)
                print(" [+] Entropy:", round(entropy, 5), "Maybe it's packed", "\n\tPossible packer ->" ,"".join(matches))

            # Optional args
            if args.sections:
                extractSections(pe)

            if args.imports:
                extractImport(pe)

            if args.exports:
                extractExports(pe)

            if args.extract_all:
                extractSections(pe)
                extractImport(pe)
                extractExports(pe)
                extractDOSHeaders(pe)
                extractNtHeader(pe)

            if args.dos_header:
                extractDOSHeaders(pe)
           
            if args.nt_header:
                extractNtHeader(pe)
        
        except:
            pefile.PEFormatError,
            FileNotFoundError,print("[!] Something went wrong!")
            exit(1)
            

# Extract architecture
def extractArch(pe):
    if hex(pe.OPTIONAL_HEADER.Magic) == "0x10b":
        print(" [+] Arch: 32bits")
    elif hex(pe.OPTIONAL_HEADER.Magic) == "0x20b":
        print(" [+] Arch: 64bits")


# Extract hash from a file
def extractHash(targetFile, vTotal):
    with open(targetFile,"rb") as f:

        bytes = f.read()

        md5hash = hashlib.md5(bytes).hexdigest()
        sha256hash = hashlib.sha256(bytes).hexdigest()

        if not vTotal:
            print("", md5hash, "(md5)\n", sha256hash, "(sha256)")
        else:
            print("", md5hash, "(md5) ->", "https://www.virustotal.com/gui/search/" + md5hash, "\n", sha256hash, "(sha256) ->", "https://www.virustotal.com/gui/search/" + sha256hash)


# Extract entropy
def extracEntropy(data: bytes) -> float:
# Count the frequency of each byte in the file
    frequencies = {}
    for byte in data:
        if byte not in frequencies:
            frequencies[byte] = 0
        frequencies[byte] += 1

    # Calculate entropy in bits per byte
    entropy = 0
    for count in frequencies.values():
        probability = count / len(data)
        entropy -= probability * math.log(probability, 2)

    return entropy


# Extract imported DLLs
def extractImport(targetFile):
    print("\n [+] Imported DLLs:")
    for entry in targetFile.DIRECTORY_ENTRY_IMPORT:
        print(" \n\t",entry.dll.decode('utf-8'))
        for func in entry.imports:
            if func.name is None:
                continue
            else:
                print("\t\t|__", func.name.decode('utf-8'))


def extractExports(targetFile):
    print("\n [+] Exported Symbols:")
    try:
        for exp in targetFile.DIRECTORY_ENTRY_EXPORT.symbols:
            print(hex(targetFile.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)
            if not exp:
                pass
            else:
                print(exp)
    except:
        print("\t ! Not exported symbols detected")
        pass


def extractDOSHeaders(targetFile):
    print("\n ==[ DOS HEADER ]==")

    if hex(targetFile.DOS_HEADER.e_magic) == "0x5a4d":
        print("\te_magic:", hex(targetFile.DOS_HEADER.e_magic), "(MZ)")
    else:
        print("\te_magic:", hex(targetFile.DOS_HEADER.e_magic))

    print("\te_lfanew:", hex(targetFile.DOS_HEADER.e_lfanew))


# Extract NT Header
def extractNtHeader(targetFile):
    print("\n ==[ NT HEADER ]==")
    if hex(targetFile.NT_HEADERS.Signature) == "0x4550":
        print("\tSignature:", hex(targetFile.NT_HEADERS.Signature), "(PE)\n")
    else:
        print("\tSignature:", hex(targetFile.NT_HEADERS.Signature), "\n")

    # Print Machine Arch
    print(" [+] _File Header:")
    if hex(targetFile.FILE_HEADER.Machine) == "0x14c":
        print("\tMachine:",hex(targetFile.FILE_HEADER.Machine), "(x86)")
    else:
        print("\tMachine:", hex(targetFile.FILE_HEADER.Machine), "(x64)")

    print("\tNumberOfSections:",hex(targetFile.FILE_HEADER.NumberOfSections))
    print("\tTimeDateStamp:",targetFile.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])
    print("\tPointerToSymbolTable:",hex(targetFile.FILE_HEADER.PointerToSymbolTable))
    print("\tNumberOfSymbols:",hex(targetFile.FILE_HEADER.NumberOfSymbols))
    print("\tSizeOfOptionalHeader:",hex(targetFile.FILE_HEADER.SizeOfOptionalHeader))
    print("\tCharacteristics:",hex(targetFile.FILE_HEADER.Characteristics))

    print("\n [+] _Optional Header:")
    if hex(targetFile.OPTIONAL_HEADER.Magic) == "0x10b":
        print("\tMagic:",hex(targetFile.OPTIONAL_HEADER.Magic), "(PE32)")
    elif hex(targetFile.OPTIONAL_HEADER.Magic) == "0x20b":
        print("\tMagic:", hex(targetFile.OPTIONAL_HEADER.Magic), "(PE32+)")
    elif hex(targetFile.OPTIONAL_HEADER.Magic) == "0x107":
        print("\tMagic:", hex(targetFile.OPTIONAL_HEADER.Magic), "(PROM)")

    print("\tMajorLinkerVersiont:",hex(targetFile.OPTIONAL_HEADER.MajorLinkerVersion))
    print("\tMinorLinkerVersiont:",hex(targetFile.OPTIONAL_HEADER.MinorLinkerVersion))
    print("\tSizeOfCode:",hex(targetFile.OPTIONAL_HEADER.SizeOfCode))
    print("\tSizeOfInitializedData:",hex(targetFile.OPTIONAL_HEADER.SizeOfInitializedData))
    print("\tSizeOfUninitializedData:",hex(targetFile.OPTIONAL_HEADER.SizeOfUninitializedData))
    print("\tAddressOfEntryPoint:",hex(targetFile.OPTIONAL_HEADER.AddressOfEntryPoint))
    print("\tBaseOfCode:",hex(targetFile.OPTIONAL_HEADER.BaseOfCode))
    print("\tBaseOfData:",hex(targetFile.OPTIONAL_HEADER.BaseOfData))
    print("\tImageBase:",hex(targetFile.OPTIONAL_HEADER.ImageBase))
    print("\tSectionAlignment:",hex(targetFile.OPTIONAL_HEADER.SectionAlignment))
    print("\tFileAlignment:",hex(targetFile.OPTIONAL_HEADER.FileAlignment))
    print("\tMajorOperatingSystemVersion:",hex(targetFile.OPTIONAL_HEADER.MajorOperatingSystemVersion))
    print("\tMinorOperatingSystemVersion:",hex(targetFile.OPTIONAL_HEADER.MinorOperatingSystemVersion))
    print("\tMajorImageVersion:",hex(targetFile.OPTIONAL_HEADER.MajorImageVersion))
    print("\tMinorImageVersion:",hex(targetFile.OPTIONAL_HEADER.MinorImageVersion))
    print("\tMajorSubsystemVersion:",hex(targetFile.OPTIONAL_HEADER.MajorSubsystemVersion))
    print("\tMinorSubsystemVersion:",hex(targetFile.OPTIONAL_HEADER.MinorSubsystemVersion))
    print("\tReserved1:",hex(targetFile.OPTIONAL_HEADER.Reserved1))
    print("\tSizeOfImage:",hex(targetFile.OPTIONAL_HEADER.SizeOfImage))
    print("\tSizeOfHeaders:",hex(targetFile.OPTIONAL_HEADER.SizeOfHeaders))
    print("\tCheckSum:",hex(targetFile.OPTIONAL_HEADER.CheckSum))
    print("\tSubsystem:",hex(targetFile.OPTIONAL_HEADER.Subsystem))
    print("\tDllCharacteristics:",hex(targetFile.OPTIONAL_HEADER.DllCharacteristics))
    print("\tSizeOfStackReserve:",hex(targetFile.OPTIONAL_HEADER.SizeOfStackReserve))
    print("\tSizeOfStackCommit:",hex(targetFile.OPTIONAL_HEADER.SizeOfStackCommit))
    print("\tSizeOfHeapReserve:",hex(targetFile.OPTIONAL_HEADER.SizeOfHeapReserve))
    print("\tSizeOfHeapCommit:",hex(targetFile.OPTIONAL_HEADER.SizeOfHeapCommit))
    print("\tLoaderFlags:",hex(targetFile.OPTIONAL_HEADER.LoaderFlags))
    print("\tNumberOfRvaAndSizes:",hex(targetFile.OPTIONAL_HEADER.NumberOfRvaAndSizes))

    print("\n\t[+] Number of data directories = %d" % targetFile.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    for data_directory in targetFile.OPTIONAL_HEADER.DATA_DIRECTORY:
#        print("\t\t",data_directory.name,"\n\t\t\t|_Size:", hex(data_directory.Size), "\n\t\t\t|_VirtualAddress:",hex(data_directory.VirtualAddress),"\n")
        print("\t\t",data_directory.name,"\t[ Size:", hex(data_directory.Size), "| VirtualAddress:",hex(data_directory.VirtualAddress),"]")

# Extract sections
def extractSections(targetFile):
    print("\n [+] Sections: ")
    print("     Nº of Sections:", targetFile.FILE_HEADER.NumberOfSections, "\n")
    for s in targetFile.sections:
        print(" section:", s.Name.decode('utf-8'))
        print("\t VirtualAddress:",hex(s.VirtualAddress))
        print("\t VirtualSize:",hex(s.Misc_VirtualSize))
        print("\t SizeOfRawData:",hex(s.SizeOfRawData))
        print("\t PointerToRawData:",hex(s.PointerToRawData))
        print("\t PointerToRelocations:",hex(s.PointerToRelocations))
        print("\t PointerToLinenumbers:",hex(s.PointerToLinenumbers))
        print("\t NumberOfRelocations:",hex(s.NumberOfRelocations))
        print("\t Characteristics:",hex(s.Characteristics))
        print("\t Entropy:", round(s.get_entropy(),5), "\n")


if __name__ == "__main__":
    main()
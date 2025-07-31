#include <Windows.h>
#include <stdio.h>


BYTE* VAFromRVA(DWORD rva, PIMAGE_NT_HEADERS nt, BYTE* base) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    //printf("hello\n");
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        DWORD sectionVA = section->VirtualAddress;
        DWORD sectionSize = section->Misc.VirtualSize;
           // printf("hello2\n");

        if (rva >= sectionVA && rva < (sectionVA + sectionSize)) {
            return base + section->PointerToRawData + (rva - sectionVA);
        }
    }

    return NULL;
}


int main(int argc, char* argv[]) {

char* word = "cfgCheck.exe";
if (argc < 2) {
    printf("Usage:\n%s <path to PE>\n%s <path to PE> -v\n", word, word);
    return 1;
};

FILE* file = fopen(argv[1], "rb");

fseek(file, 0, SEEK_END);
size_t size = ftell(file);
fseek(file, 0, SEEK_SET);

BYTE* buff = malloc(size);

if (!fread(buff, 1, size, file )) {
    printf("error\n");
    return 1;
 }

PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)buff;
if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Invalid PE file\n");
    return 1;
}

PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
if (nt->Signature != IMAGE_NT_SIGNATURE) {
    printf("error 2\n");
    return 1;
}


PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

if (oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
    printf("Does not have any imports.\n");
    return 1;
}

PIMAGE_LOAD_CONFIG_DIRECTORY64  id = (PIMAGE_LOAD_CONFIG_DIRECTORY64)VAFromRVA(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, nt, buff);
if (!id) {
    printf("error\n");
    return 1;
}

if (argv[2]) {
printf("GuardFlags: 0x%08X\n", id->GuardFlags);
printf("Size: 0x%08X\n", id->Size);
printf("TimeDateStamp: 0x%08X\n", id->TimeDateStamp);
printf("MajorVersion: 0x%04X\n", id->MajorVersion);
printf("MinorVersion: 0x%04X\n", id->MinorVersion);
printf("GlobalFlagsClear: 0x%08X\n", id->GlobalFlagsClear);
printf("GlobalFlagsSet: 0x%08X\n", id->GlobalFlagsSet);
printf("CriticalSectionDefaultTimeout: 0x%08X\n", id->CriticalSectionDefaultTimeout);
printf("DeCommitFreeBlockThreshold: 0x%016llX\n", id->DeCommitFreeBlockThreshold);
printf("DeCommitTotalFreeThreshold: 0x%016llX\n", id->DeCommitTotalFreeThreshold);
printf("LockPrefixTable: 0x%016llX\n", id->LockPrefixTable);
printf("MaximumAllocationSize: 0x%016llX\n", id->MaximumAllocationSize);
printf("VirtualMemoryThreshold: 0x%016llX\n", id->VirtualMemoryThreshold);
printf("ProcessAffinityMask: 0x%016llX\n", id->ProcessAffinityMask);
printf("ProcessHeapFlags: 0x%08X\n", id->ProcessHeapFlags);
printf("CSDVersion: 0x%04X\n", id->CSDVersion);
printf("DependentLoadFlags: 0x%04X\n", id->DependentLoadFlags);
printf("EditList: 0x%016llX\n", id->EditList);
printf("SecurityCookie: 0x%016llX\n", id->SecurityCookie);
printf("SEHandlerTable: 0x%016llX\n", id->SEHandlerTable);
printf("SEHandlerCount: 0x%016llX\n", id->SEHandlerCount);
printf("GuardCFCheckFunctionPointer: 0x%016llX\n", id->GuardCFCheckFunctionPointer);
printf("GuardCFDispatchFunctionPointer: 0x%016llX\n", id->GuardCFDispatchFunctionPointer);
printf("GuardCFFunctionTable: 0x%016llX\n", id->GuardCFFunctionTable);
printf("GuardCFFunctionCount: 0x%016llX\n", id->GuardCFFunctionCount);

// CodeIntegrity is a nested struct—printf this based on how you define IMAGE_LOAD_CONFIG_CODE_INTEGRITY
// Example:
printf("CodeIntegrity.Flags: 0x%04X\n", id->CodeIntegrity.Flags);
printf("CodeIntegrity.Catalog: 0x%04X\n", id->CodeIntegrity.Catalog);
printf("CodeIntegrity.CatalogOffset: 0x%04X\n", id->CodeIntegrity.CatalogOffset);
printf("CodeIntegrity.Reserved: 0x%04X\n", id->CodeIntegrity.Reserved);

printf("GuardAddressTakenIatEntryTable: 0x%016llX\n", id->GuardAddressTakenIatEntryTable);
printf("GuardAddressTakenIatEntryCount: 0x%016llX\n", id->GuardAddressTakenIatEntryCount);
printf("GuardLongJumpTargetTable: 0x%016llX\n", id->GuardLongJumpTargetTable);
printf("GuardLongJumpTargetCount: 0x%016llX\n", id->GuardLongJumpTargetCount);
printf("DynamicValueRelocTable: 0x%016llX\n", id->DynamicValueRelocTable);
printf("CHPEMetadataPointer: 0x%016llX\n", id->CHPEMetadataPointer);
printf("GuardRFFailureRoutine: 0x%016llX\n", id->GuardRFFailureRoutine);
printf("GuardRFFailureRoutineFunctionPointer: 0x%016llX\n", id->GuardRFFailureRoutineFunctionPointer);
printf("DynamicValueRelocTableOffset: 0x%08X\n", id->DynamicValueRelocTableOffset);
printf("DynamicValueRelocTableSection: 0x%04X\n", id->DynamicValueRelocTableSection);
printf("Reserved2: 0x%04X\n", id->Reserved2);
printf("GuardRFVerifyStackPointerFunctionPointer: 0x%016llX\n", id->GuardRFVerifyStackPointerFunctionPointer);
printf("HotPatchTableOffset: 0x%08X\n", id->HotPatchTableOffset);
printf("Reserved3: 0x%08X\n", id->Reserved3);
printf("EnclaveConfigurationPointer: 0x%016llX\n", id->EnclaveConfigurationPointer);
printf("VolatileMetadataPointer: 0x%016llX\n", id->VolatileMetadataPointer);
printf("GuardEHContinuationTable: 0x%016llX\n", id->GuardEHContinuationTable);
printf("GuardEHContinuationCount: 0x%016llX\n", id->GuardEHContinuationCount);
printf("GuardXFGCheckFunctionPointer: 0x%016llX\n", id->GuardXFGCheckFunctionPointer);
printf("GuardXFGDispatchFunctionPointer: 0x%016llX\n", id->GuardXFGDispatchFunctionPointer);
printf("GuardXFGTableDispatchFunctionPointer: 0x%016llX\n", id->GuardXFGTableDispatchFunctionPointer);
printf("CastGuardOsDeterminedFailureMode: 0x%016llX\n", id->CastGuardOsDeterminedFailureMode);
printf("GuardMemcpyFunctionPointer: 0x%016llX\n", id->GuardMemcpyFunctionPointer);
}

if (id->GuardFlags != 0) {
    printf("CFG protections FOUND on - %s\n", argv[1]);
    if (id->GuardFlags == 0x00417500) {
        printf("XFG enabled\n");
    }
} else {
    printf("*No CFG detected on - [%s]*\n", argv[1]);
}

return 0;
}
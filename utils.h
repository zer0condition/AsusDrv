#pragma once

namespace SuperFetch
{//https://github.com/jonomango/superfetch
    enum SUPERFETCH_INFORMATION_CLASS {
        SuperfetchRetrieveTrace = 1,  // Query
        SuperfetchSystemParameters = 2,  // Query
        SuperfetchLogEvent = 3,  // Set
        SuperfetchGenerateTrace = 4,  // Set
        SuperfetchPrefetch = 5,  // Set
        SuperfetchPfnQuery = 6,  // Query
        SuperfetchPfnSetPriority = 7,  // Set
        SuperfetchPrivSourceQuery = 8,  // Query
        SuperfetchSequenceNumberQuery = 9,  // Query
        SuperfetchScenarioPhase = 10, // Set
        SuperfetchWorkerPriority = 11, // Set
        SuperfetchScenarioQuery = 12, // Query
        SuperfetchScenarioPrefetch = 13, // Set
        SuperfetchRobustnessControl = 14, // Set
        SuperfetchTimeControl = 15, // Set
        SuperfetchMemoryListQuery = 16, // Query
        SuperfetchMemoryRangesQuery = 17, // Query
        SuperfetchTracingControl = 18, // Set
        SuperfetchTrimWhileAgingControl = 19,
        SuperfetchInformationMax = 20
    };

    struct SUPERFETCH_INFORMATION {
        ULONG                        Version = 45;
        ULONG                        Magic = 'kuhC';
        SUPERFETCH_INFORMATION_CLASS InfoClass;
        PVOID                        Data;
        ULONG                        Length;
    };

    struct MEMORY_FRAME_INFORMATION {
        ULONGLONG UseDescription : 4;
        ULONGLONG ListDescription : 3;
        ULONGLONG Reserved0 : 1;
        ULONGLONG Pinned : 1;
        ULONGLONG DontUse : 48;
        ULONGLONG Priority : 3;
        ULONGLONG Reserved : 4;
    };

    struct FILEOFFSET_INFORMATION {
        ULONGLONG DontUse : 9;
        ULONGLONG Offset : 48;
        ULONGLONG Reserved : 7;
    };

    struct PAGEDIR_INFORMATION {
        ULONGLONG DontUse : 9;
        ULONGLONG PageDirectoryBase : 48;
        ULONGLONG Reserved : 7;
    };

    struct UNIQUE_PROCESS_INFORMATION {
        ULONGLONG DontUse : 9;
        ULONGLONG UniqueProcessKey : 48;
        ULONGLONG Reserved : 7;
    };

    struct MMPFN_IDENTITY {
        union {
            MEMORY_FRAME_INFORMATION   e1;
            FILEOFFSET_INFORMATION     e2;
            PAGEDIR_INFORMATION        e3;
            UNIQUE_PROCESS_INFORMATION e4;
        } u1;
        SIZE_T PageFrameIndex;
        union {
            struct {
                ULONG Image : 1;
                ULONG Mismatch : 1;
            } e1;
            PVOID FileObject;
            PVOID UniqueFileObjectKey;
            PVOID ProtoPteAddress;
            PVOID VirtualAddress;
        } u2;
    };

    struct SYSTEM_MEMORY_LIST_INFORMATION {
        SIZE_T    ZeroPageCount;
        SIZE_T    FreePageCount;
        SIZE_T    ModifiedPageCount;
        SIZE_T    ModifiedNoWritePageCount;
        SIZE_T    BadPageCount;
        SIZE_T    PageCountByPriority[8];
        SIZE_T    RepurposedPagesByPriority[8];
        ULONG_PTR ModifiedPageCountPageFile;
    };

    struct PF_PFN_PRIO_REQUEST {
        ULONG                          Version;
        ULONG                          RequestFlags;
        SIZE_T                         PfnCount;
        SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
        MMPFN_IDENTITY                 PageData[ANYSIZE_ARRAY];
    };

    struct PF_PHYSICAL_MEMORY_RANGE {
        ULONG_PTR BasePfn;
        ULONG_PTR PageCount;
    };

    struct PF_MEMORY_RANGE_INFO_V1 {
        ULONG Version = 1;
        ULONG RangeCount;
        PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
    };

    struct PF_MEMORY_RANGE_INFO_V2 {
        ULONG Version = 2;
        ULONG Flags;
        ULONG RangeCount;
        PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
    };

    inline constexpr ULONG SE_PROF_SINGLE_PROCESS_PRIVILEGE = 13;
    inline constexpr ULONG SE_DEBUG_PRIVILEGE = 20;

    inline constexpr SYSTEM_INFORMATION_CLASS SystemSuperfetchInformation = SYSTEM_INFORMATION_CLASS(79);

    extern "C" NTSYSAPI NTSTATUS RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

    struct memory_range {
        std::uint64_t pfn = 0;
        std::size_t page_count = 0;
    };

    enum class spf_error {
        raise_privilege,
        query_ranges,
        query_pfn
    };

    using memory_ranges = std::vector<memory_range>;
    using memory_translations = std::unordered_map<void const*, std::uint64_t>;

    class memory_map {
    public:
        // Create a snapshot of the current system memory map.
        static std::expected<memory_map, spf_error> current();

        // Translate a virtual address to a physical address.
        std::uint64_t translate(void const* address) const;

        // Get a vector of physical memory ranges.
        memory_ranges const& ranges() const;

        // Get a map of virtual to physical page translations.
        memory_translations const& translations() const;

    private:
        static bool raise_privilege();

        static memory_ranges query_memory_ranges();
        static memory_ranges query_memory_ranges_v1();
        static memory_ranges query_memory_ranges_v2();

        static NTSTATUS query_superfetch_info(
            SUPERFETCH_INFORMATION_CLASS info_class,
            PVOID                        buffer,
            ULONG                        length,
            PULONG                       return_length = nullptr
        );

    private:
        // Contiguous physical memory ranges.
        memory_ranges ranges_ = {};

        // Virtual to physical page translations.
        memory_translations translations_ = {};
    };

    // Take a snapshot of the current system memory map.
    inline std::expected<memory_map, spf_error> memory_map::current() {
        if (!raise_privilege())
            return std::unexpected(spf_error::raise_privilege);

        memory_map mm = {};
        mm.ranges_ = query_memory_ranges();

        if (mm.ranges_.empty())
            return std::unexpected(spf_error::query_ranges);

        for (auto const& [base_pfn, page_count] : mm.ranges_) {
            // This is a bit too big, but its not a big deal.
            std::size_t const buffer_length = sizeof(PF_PFN_PRIO_REQUEST) +
                sizeof(MMPFN_IDENTITY) * page_count;

            auto const buffer = std::make_unique<std::uint8_t[]>(buffer_length);
            auto const request = reinterpret_cast<PF_PFN_PRIO_REQUEST*>(buffer.get());
            request->Version = 1;
            request->RequestFlags = 1;
            request->PfnCount = page_count;

            for (std::uint64_t i = 0; i < page_count; ++i)
                request->PageData[i].PageFrameIndex = base_pfn + i;

            if (!NT_SUCCESS(query_superfetch_info(
                SuperfetchPfnQuery, request, buffer_length)))
                return std::unexpected(spf_error::query_pfn);

            for (std::uint64_t i = 0; i < page_count; ++i) {
                // Cache the translation for this page.
                if (void const* const virt = request->PageData[i].u2.VirtualAddress)
                    mm.translations_[virt] = (base_pfn + i) << 12;
            }
        }

        return mm;
    }

    // Translate a virtual address to a physical address.
    inline std::uint64_t memory_map::translate(void const* const address) const {
        // Align to the lowest page boundary.
        void const* const aligned = reinterpret_cast<void const*>(
            reinterpret_cast<std::uint64_t>(address) & ~0xFFFull);

        auto const it = translations_.find(aligned);
        if (it == end(translations_))
            return 0;

        return it->second + (reinterpret_cast<std::uint64_t>(address) & 0xFFF);
    }

    // Get a vector of physical memory ranges.
    inline memory_ranges const& memory_map::ranges() const {
        return ranges_;
    }

    // Get a map of virtual to physical page translations.
    inline memory_translations const& memory_map::translations() const {
        return translations_;
    }

    inline bool memory_map::raise_privilege() {
        BOOLEAN old = FALSE;

        if (!NT_SUCCESS(RtlAdjustPrivilege(
            SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &old)))
            return false;

        if (!NT_SUCCESS(RtlAdjustPrivilege(
            SE_DEBUG_PRIVILEGE, TRUE, FALSE, &old)))
            return false;

        return true;
    }

    inline memory_ranges memory_map::query_memory_ranges() {
        auto ranges = query_memory_ranges_v1();
        if (ranges.empty())
            return query_memory_ranges_v2();
        return ranges;
    }

    inline memory_ranges memory_map::query_memory_ranges_v1() {
        ULONG buffer_length = 0;

        // STATUS_BUFFER_TOO_SMALL.
        if (PF_MEMORY_RANGE_INFO_V1 info = {}; 0xC0000023 != query_superfetch_info(
            SuperfetchMemoryRangesQuery, &info, sizeof(info), &buffer_length))
            return {};

        auto const buffer = std::make_unique<std::uint8_t[]>(buffer_length);
        auto const info = reinterpret_cast<PF_MEMORY_RANGE_INFO_V1*>(buffer.get());
        info->Version = 1;

        if (!NT_SUCCESS(query_superfetch_info(
            SuperfetchMemoryRangesQuery, info, buffer_length)))
            return {};

        memory_ranges ranges = {};

        for (std::uint32_t i = 0; i < info->RangeCount; ++i) {
            ranges.push_back({
              .pfn = info->Ranges[i].BasePfn,
              .page_count = info->Ranges[i].PageCount
                });
        }

        return ranges;
    }

    inline memory_ranges memory_map::query_memory_ranges_v2() {
        ULONG buffer_length = 0;

        // STATUS_BUFFER_TOO_SMALL.
        if (PF_MEMORY_RANGE_INFO_V2 info = {}; 0xC0000023 != query_superfetch_info(
            SuperfetchMemoryRangesQuery, &info, sizeof(info), &buffer_length))
            return {};

        auto const buffer = std::make_unique<std::uint8_t[]>(buffer_length);
        auto const info = reinterpret_cast<PF_MEMORY_RANGE_INFO_V2*>(buffer.get());
        info->Version = 2;

        if (!NT_SUCCESS(query_superfetch_info(
            SuperfetchMemoryRangesQuery, info, buffer_length)))
            return {};

        memory_ranges ranges = {};

        for (std::uint32_t i = 0; i < info->RangeCount; ++i) {
            ranges.push_back({
              .pfn = info->Ranges[i].BasePfn,
              .page_count = info->Ranges[i].PageCount
                });
        }

        return ranges;
    }

    inline NTSTATUS memory_map::query_superfetch_info(
        SUPERFETCH_INFORMATION_CLASS info_class,
        PVOID                        buffer,
        ULONG                        length,
        PULONG                       return_length
    ) {
        SUPERFETCH_INFORMATION superfetch_info = {
          .InfoClass = info_class,
          .Data = buffer,
          .Length = length
        };

        return NtQuerySystemInformation(SystemSuperfetchInformation,
            &superfetch_info, sizeof(superfetch_info), return_length);
    }
} // SuperFetch


bool MatchSign(PUCHAR Data, PUCHAR Sign, int Size)
{
    for (int i = 0; i < Size; i++) {
        if (Sign[i] == 0xff) {
            continue;
        }
        if (Sign[i] != Data[i]) {
            return false;
        }
    }
    return true;
}

ULONG64 GetKernelObject(ULONG TargetProcessId, HANDLE TargetHandle)
{
    NTSTATUS Status = 0;
    ULONG64 Result = 0;

    PSYSTEM_HANDLE_INFORMATION pHandleInfo = nullptr;
    ULONG ulBytes = 0;

    while ((Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, pHandleInfo, ulBytes, &ulBytes)) == 0xC0000004L)
    {
        if (pHandleInfo != nullptr)
        {
            pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pHandleInfo, (size_t)2 * ulBytes));
        }
        else
        {
            pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)2 * ulBytes));
        }
    }

    if (Status != 0) {
        goto done;
    }

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++)
    {
        if ((pHandleInfo->Handles[i].UniqueProcessId == TargetProcessId) && (pHandleInfo->Handles[i].HandleValue == reinterpret_cast<USHORT>(TargetHandle)))
        {
            Result = reinterpret_cast<ULONG64>(pHandleInfo->Handles[i].Object);
            break;
        }
    }

done:
    if (pHandleInfo != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pHandleInfo);
    }

    return Result;
}

ULONG GetProcessIdByName(const wchar_t* ProcessName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, ProcessName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

uint64_t GetEProcess(ULONG processId) 
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess == NULL) return 0;

    uint64_t eprocess = GetKernelObject(GetCurrentProcessId(), hProcess);
    CloseHandle(hProcess);
    return eprocess;
}


std::wstring GetProcessPath(const std::wstring& process_name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return L"";
    }

    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, process_name.c_str()) == 0) {
                CloseHandle(hSnapshot);

                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processEntry.th32ProcessID);
                if (hProcess != nullptr) {
                    wchar_t buffer[MAX_PATH];
                    DWORD bufferSize = MAX_PATH;

                    if (QueryFullProcessImageName(hProcess, 0, buffer, &bufferSize)) {
                        CloseHandle(hProcess);
                        return buffer;
                    }

                    CloseHandle(hProcess);
                }

                return L"";
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);

    return L"";
}

uintptr_t GetProcessBase(const std::wstring& process_name)
{
    return (uintptr_t)LoadLibrary(GetProcessPath(process_name).c_str());
}


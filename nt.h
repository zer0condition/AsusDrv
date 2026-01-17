#pragma once

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

#define IS_LARGE_PAGE(x)    ( (BOOLEAN)((x >> 7) & 1) )
#define IS_PAGE_PRESENT(x)  ( (BOOLEAN)(x & 1) )

#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_1GB_SHIFT)) )

#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_2MB_SHIFT)) )

#define PAGE_4KB_SHIFT      12
#define PAGE_4KB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_4KB_SHIFT)) )

#pragma warning(push)
#pragma warning(disable:4214)


typedef union _VIRTUAL_MEMORY_ADDRESS
{
    struct
    {
        UINT64 PageIndex : 12;  /* 0:11  */
        UINT64 PtIndex : 9;   /* 12:20 */
        UINT64 PdIndex : 9;   /* 21:29 */
        UINT64 PdptIndex : 9;   /* 30:38 */
        UINT64 Pml4Index : 9;   /* 39:47 */
        UINT64 Unused : 16;  /* 48:63 */
    } Bits;
    UINT64 All;
} VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;


typedef union _DIRECTORY_TABLE_BASE
{
    struct
    {
        UINT64 Ignored0 : 3;    /* 2:0   */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 _Ignored1 : 7;    /* 11:5  */
        UINT64 PhysicalAddress : 36;   /* 47:12 */
        UINT64 _Reserved0 : 16;   /* 63:48 */
    } Bits;
    UINT64 All;
} CR3, DIR_TABLE_BASE;

typedef union _PML4_ENTRY
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 _Ignored0 : 1;    /* 6     */
        UINT64 _Reserved0 : 1;    /* 7     */
        UINT64 _Ignored1 : 4;    /* 11:8  */
        UINT64 PhysicalAddress : 40;   /* 51:12 */
        UINT64 _Ignored2 : 11;   /* 62:52 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PML4E;


typedef union _PDPT_ENTRY_LARGE
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 Dirty : 1;    /* 6     */
        UINT64 PageSize : 1;    /* 7     */
        UINT64 Global : 1;    /* 8     */
        UINT64 _Ignored0 : 3;    /* 11:9  */
        UINT64 PageAttributeTable : 1;    /* 12    */
        UINT64 _Reserved0 : 17;   /* 29:13 */
        UINT64 PhysicalAddress : 22;   /* 51:30 */
        UINT64 _Ignored1 : 7;    /* 58:52 */
        UINT64 ProtectionKey : 4;    /* 62:59 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PDPTE_LARGE;


typedef union _PDPT_ENTRY
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 _Ignored0 : 1;    /* 6     */
        UINT64 PageSize : 1;    /* 7     */
        UINT64 _Ignored1 : 4;    /* 11:8  */
        UINT64 PhysicalAddress : 40;   /* 51:12 */
        UINT64 _Ignored2 : 11;   /* 62:52 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PDPTE;


typedef union _PD_ENTRY_LARGE
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 Dirty : 1;    /* 6     */
        UINT64 PageSize : 1;    /* 7     */
        UINT64 Global : 1;    /* 8     */
        UINT64 _Ignored0 : 3;    /* 11:9  */
        UINT64 PageAttributeTalbe : 1;    /* 12    */
        UINT64 _Reserved0 : 8;    /* 20:13 */
        UINT64 PhysicalAddress : 29;   /* 49:21 */
        UINT64 _Reserved1 : 2;    /* 51:50 */
        UINT64 _Ignored1 : 7;    /* 58:52 */
        UINT64 ProtectionKey : 4;    /* 62:59 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PDE_LARGE;

typedef union _PD_ENTRY
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 _Ignored0 : 1;    /* 6     */
        UINT64 PageSize : 1;    /* 7     */
        UINT64 _Ignored1 : 4;    /* 11:8  */
        UINT64 PhysicalAddress : 38;   /* 49:12 */
        UINT64 _Reserved0 : 2;    /* 51:50 */
        UINT64 _Ignored2 : 11;   /* 62:52 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PDE;


typedef union _PT_ENTRY
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 Dirty : 1;    /* 6     */
        UINT64 PageAttributeTable : 1;    /* 7     */
        UINT64 Global : 1;    /* 8     */
        UINT64 _Ignored0 : 3;    /* 11:9  */
        UINT64 PhysicalAddress : 38;   /* 49:12 */
        UINT64 _Reserved0 : 2;    /* 51:50 */
        UINT64 _Ignored1 : 7;    /* 58:52 */
        UINT64 ProtectionKey : 4;    /* 62:59 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PTE;

typedef union _MMPTE_HARDWARE
{
    struct
    {
        UINT64 Valid : 1;    /* 0     */
        UINT64 Dirty1 : 1;    /* 1     */
        UINT64 Owner : 1;    /* 2     */
        UINT64 WriteThrough : 1;    /* 3     */
        UINT64 CacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 Dirty : 1;    /* 6     */
        UINT64 LargePage : 1;    /* 7     */
        UINT64 Global : 1;    /* 8     */
        UINT64 CopyOnWrite : 1;    /* 9     */
        UINT64 Unused : 1;    /* 10    */
        UINT64 Write : 1;    /* 11    */
        UINT64 PageFrameNumber : 36;   /* 47:12 */
        UINT64 ReservedForHardware : 4;    /* 51:48 */
        UINT64 ReservedForSoftware : 4;    /* 55:52 */
        UINT64 WsleAge : 4;    /* 59:56 */
        UINT64 WsleProtection : 3;    /* 62:60 */
        UINT64 NoExecute : 1;    /* 63 */
    } Bits;
    UINT64 All;
} MMPTE_HARDWARE;

#pragma warning(pop)


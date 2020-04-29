// references:
// https://www.buaq.net/go-20582.html (64位系统，未考虑wow64)
// https://github.com/bowlofstew/rootkit.com/blob/master/cardmagic/PortHidDemo_Vista.c (64位系统，未考虑wow64)
//
// google keyword
// nsiproxy hook
// IOCTL_NSI_GETALLPARAM

typedef struct _NSI_STATUS_ENTRY
{
    ULONG_PTR dwState;
    ULONG_PTR Unknown1;
} NSI_STATUS_ENTRY, *PNSI_STATUS_ENTRY;

typedef struct _NSI_PROCESSID_INFO
{
    ULONG dwUdpProId;
    ULONG UnknownParam2;
    ULONG UnknownParam3;
    ULONG dwTcpProId;
    ULONG UnknownParam5;
    ULONG UnknownParam6;
    ULONG UnknownParam7;
    ULONG UnknownParam8;
} NSI_PROCESSID_INFO, *PNSI_PROCESSID_INFO;

typedef struct _INTERNAL_TCP_TABLE_SUBENTRY
{
    USHORT Unknown1;
    USHORT Port;
    ULONG dwIP;
    UCHAR Unknown2[20];
} INTERNAL_TCP_TABLE_SUBENTRY, *PINTERNAL_TCP_TABLE_SUBENTRY;
 
typedef struct _INTERNAL_TCP_TABLE_ENTRY
{
    INTERNAL_TCP_TABLE_SUBENTRY localEntry;
    INTERNAL_TCP_TABLE_SUBENTRY remoteEntry;
} INTERNAL_TCP_TABLE_ENTRY, *PINTERNAL_TCP_TABLE_ENTRY;

typedef struct _NSI_PARAM // NSI_PARAM 64bit: 0x70 = 112
{     
    ULONG_PTR UnknownParam1;
    ULONG_PTR UnknownParam2;
    ULONG_PTR UnknownParam3;
    ULONG_PTR UnknownParam4;
    ULONG_PTR UnknownParam5;
    PINTERNAL_TCP_TABLE_ENTRY lpEntries;
    ULONG lpType;
    ULONG_PTR UnknownParam8;
    ULONG_PTR UnknownParam9;
    PNSI_STATUS_ENTRY lpStatus;
    ULONG_PTR UnknownParam11;
    PNSI_PROCESSID_INFO lpProcInfo;
    ULONG_PTR UnknownParam13;
    ULONG Count;
} NSI_PARAM, *PNSI_PARAM;

typedef struct _NSI_PARAMS32 // NSI_PARAM in wow64: 0x3C
{
    ULONG UnknownParam1; //0x0000
    char pad_0004[8]; //0x0004
    ULONG lpType; //0x000C
    char pad_0010[8]; //0x0010
    ULONG lpEntries; //0x0018
    ULONG AddrEntrySize; //0x001C
    char pad_0020[8]; //0x0020
    ULONG lpStatus; //0x0028
    ULONG NeighborTableEntrySize; //0x002C
    ULONG lpProcInfo; //0x0030
    ULONG StateTableEntrySize; //0x0034
    ULONG Count; //0x0038
    char pad_003C[4]; //0x003C
} NSI_PARAM32, *PNSI_PARAM32;

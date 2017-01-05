#ifndef _METERPRETER_SERVER_SETUP_WINDNS
#define _METERPRETER_SERVER_SETUP_WINDNS

#define MAX_DNS_NAME_SIZE 253
#define MAX_DNS_SUBNAME_SIZE 62

#pragma pack(push, 1)
typedef struct _IncapuslatedDns
{
	USHORT size;
	PUCHAR packet;
	USHORT status;
} IncapuslatedDns;


typedef struct _DnsReverseHeader
{
	BYTE next_sub_seq[8];
	BYTE status_flag;
	DWORD size;
	BYTE reserved;
} DnsReverseHeader;


typedef union _DnsData
{
	BYTE data[14];
	DnsReverseHeader header;
} DnsData;

typedef struct _DnsTunnel
{
	BYTE ff;
	BYTE index_size;
	DnsData block;

} DnsTunnel;
#pragma pack(pop)


void transport_write_dns_config(Transport* transport, MetsrvTransportDns* config);
Transport* transport_create_dns(MetsrvTransportDns* config);

#endif
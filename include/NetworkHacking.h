#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <Windows.h>
#include <mstcpip.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

using std::string;
using std::cout;
using std::ofstream;

#define ICMP_PROTOCOL		1
#define IGMP_PROTOCOL		2
#define TCP_PROTOCOL		6
#define UDP_PROTOCOL		17

#define ECHO_REPLY			0
#define ECHO_REQUEST		8
#define TTL_EXPIRED			11

#define MAX_TTL				255

struct IPV4_HDR
{
	unsigned char ip_header_len : 4;		//Header length
	unsigned char ip_version : 4;			//4 bit IPv4 version
	unsigned char ip_tos;					//IP type of service
	unsigned short ip_total_lenght;			//Total lenght
	unsigned short ip_id;					//Unique identifier

	unsigned char ip_frag_offset : 5;		//Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1;			//Fragment offset

	unsigned char ip_ttl;					//Time to live
	unsigned char ip_protocol;				//Protocol(TCP | UDP | ICMP etc..)
	unsigned short ip_checksum;				//IP checksum
	unsigned int ip_srcaddr;				//Source address
	unsigned int ip_destaddr;				//Destination address
};

using PIPV4_HDR = IPV4_HDR*;

struct UDP_HDR
{
	unsigned short source_port;				//Source port
	unsigned short dest_port;				//Destination port
	unsigned short udp_length;				//UDP packet length
	unsigned short udp_checksum;			//UDP checksum(opt)
};

using PUDP_HDR = UDP_HDR*;

struct TCP_HDR
{
	unsigned short source_port;				//Source port
	unsigned short dest_port;				//Dest port
	unsigned int sequence;					//Sequence number - 32 bits
	unsigned int acknowledge;				//Acknowledge number - 32 bits

	unsigned char ns : 1;					//Nonce sumflag added in RFC 3540
	unsigned char reserved_part1 : 3;		//According to rfc
	unsigned char data_offset : 4;			/*   The number of 32 bit words in the TCP header
												 This indicats where the data begins
											*/
	unsigned char fin : 1;					//Finish flag
	unsigned char syn : 1;					//Synchronise flag
	unsigned char rst : 1;					//Reset flag
	unsigned char psh : 1;					//Push flag
	unsigned char ack : 1;					//Acknowledgement flag
	unsigned char urg : 1;					//Echo flag

	unsigned char ecn : 1;					//ECN_Echo
	unsigned char cwr : 1;					//Congestion Window Reduced Flag

	unsigned short window;					//Window
	unsigned short checksum;				//Checksum
	unsigned short urgent_pointer;			//Urgent pointer
};

using PTCP_HDR = TCP_HDR*;

struct ICMP_HDR
{
	BYTE type;								//ICMP Error type
	BYTE code;								//Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
};

using PICMP_HDR = ICMP_HDR*;

struct ETHERNET_HDR
{
	unsigned char dest[6];			//Mac of gateway
	unsigned char source[6];		//Mac of interface
	USHORT type;					//IP, ARP, ICMP..
};

using PETHERNET_HDR = ETHERNET_HDR*;

inline string __fastcall ReceiveBySocket(
	__in CONST SOCKET Socket,
	__out_opt PINT ByteReceived,
	__out PINT Error						//Fails if Error == NULL
)
{
	if (!Error) return string{};

	*Error = 0;
	string msg;
	int i = 0;

	for (; ; ++i)
	{
		msg += '\0';
		if (recv(Socket, &msg[0] + i, 1, 0) == SOCKET_ERROR)
		{
			*Error = WSAGetLastError();
			return string{};
		}
		if (!msg[i])break;
	}

	if (ByteReceived)
		*ByteReceived = i;

	return string{ &msg[0],&msg[msg.length() - 1] };
}

inline int __fastcall doRecv(
	__in CONST SOCKET Socketfd,
	__in __out char* base,
	__in int ByteToRecv
)
{
	int ByteWorked = ByteToRecv;
	while (ByteToRecv > 0)
	{
		int ret = recv(Socketfd, base, 1, 0);
		if (ret < 0)
			return SOCKET_ERROR;
		ByteToRecv -= ret;
		base += ret;
	}

	return ByteWorked - ByteToRecv;
}

inline int __fastcall doSend(
	__in CONST SOCKET Socketfd,
	__in __out char* base,
	__in int ByteToSend
)
{
	int ByteSent = 0;
	
	while (ByteSent < ByteToSend)
	{
		int bByte = send(Socketfd, base, ByteToSend, 0);
		if (bByte == SOCKET_ERROR)
			return SOCKET_ERROR;
		ByteSent += bByte;
		base += bByte;
	}

	return ByteSent;
}

inline size_t __fastcall SendBySocket(
	__in CONST SOCKET Socketfd,
	__in CONST string& s
)
{
	/*size_t ByteToSend = s.length() * sizeof(char) + sizeof(char);
	size_t ByteSent = 0, Error = NO_ERROR;
	const char* pBuffer = &s[0];

	while (ByteSent < ByteToSend)
	{
		int bByte = send(Socketfd, pBuffer, (int)ByteToSend, 0);
		if (bByte == SOCKET_ERROR)
			return SOCKET_ERROR;
		ByteSent += bByte;
		pBuffer += bByte;
	}
	
	return ByteSent;*/
	return doSend(Socketfd, (char*)&s[0], (int)s.length() * sizeof(char) + sizeof(char));
}

inline int __fastcall ReceiveFileBySocket(
	__in CONST SOCKET Socketfd,
	__in CONST HANDLE hFile,
	__in CONST int ByteToRecv,
	__in __out int* Error
)
{
	#define BUFF_SIZE 65535
	char* buffer = NULL;
	int ByteRet = NO_ERROR;
	int dwSize = ByteToRecv;

	if (!(buffer = new char[BUFF_SIZE]))
		return ByteRet;
	
	SecureZeroMemory(buffer, BUFF_SIZE);

	while (ByteRet < dwSize)
	{
		int ByteRead = doRecv(Socketfd, buffer, ((dwSize - ByteRet - 1) % BUFF_SIZE) + 1);
		if (ByteRead == SOCKET_ERROR)
		{
			if (Error)
				*Error = GetLastError();
			break;
		}

		if (!WriteFile(
			hFile,
			buffer,
			ByteRead,
			NULL,
			NULL
		))
			if (Error)
				*Error = GetLastError();

		ByteRet += ByteRead;
	}

	if (buffer)
		delete[]buffer;
	
	return ByteRet;
}

inline int __fastcall SendFileBySocket(
	__in CONST SOCKET Socketfd,
	__in CONST HANDLE hFile,
	__in __out int *Error
)
{
	#define BUFF_SIZE 65535
	#define BYTES_TO_READ_AT_TIME 65535

	char* buffer = NULL;
	BOOL bEof = FALSE;
	DWORD dwBytesRead = 0;
	int ByteSent = 0;

	if (!(buffer = new char[BUFF_SIZE]))
		return ByteSent;

	SecureZeroMemory(buffer, BUFF_SIZE);

	do
	{
		if (!ReadFile(
			hFile,
			buffer,
			BYTES_TO_READ_AT_TIME,
			&dwBytesRead,
			NULL
		))
			if (Error)
				*Error = GetLastError();

		if (dwBytesRead < BYTES_TO_READ_AT_TIME)
			bEof = TRUE;

		if (doSend(Socketfd, buffer, dwBytesRead) == SOCKET_ERROR)
		{
			if (Error)
				*Error = GetLastError();
			ByteSent = SOCKET_ERROR;
			break;
		}

		ByteSent += dwBytesRead;

	} while (!bEof);

	if (buffer)
		delete[]buffer;
	
	return ByteSent;
}

inline INT __fastcall GetMAC(
	CONST string& ip,
	BYTE* MacRet
)
{
	IPAddr Destination = inet_addr(ip.c_str());
	IPAddr Source = INADDR_ANY;
	ULONG Mac[2];
	ULONG MacLength = 6;
	memset(&Mac, 0xff, sizeof(Mac));

	SendARP(Destination, Source, &Mac, &MacLength);

	if (MacLength)
	{
		BYTE* pbPhysicalAddress = (BYTE*)&Mac;
		for (UINT i = 0; i < MacLength; ++i)
			MacRet[i] = pbPhysicalAddress[i];
		return FALSE;
	}

	return TRUE;
}

inline INT __fastcall GetMAC_c(
	CONST char* ip,
	BYTE* MacRet
)
{
	IPAddr Destination = inet_addr(ip);
	IPAddr Source = INADDR_ANY;
	ULONG Mac[2];
	ULONG MacLength = 6;
	memset(&Mac, 0xff, sizeof(Mac));

	SendARP(Destination, Source, &Mac, &MacLength);

	if (MacLength)
	{
		BYTE* pbPhysicalAddress = (BYTE*)&Mac;
		for (UINT i = 0; i < MacLength; ++i)
			MacRet[i] = pbPhysicalAddress[i];
		return FALSE;
	}

	return TRUE;
}

inline INT __fastcall GetGateway(
	CONST in_addr ip,
	string& Address
)
{
	IP_ADAPTER_INFO* IpAdapterInfo = NULL;
	IP_ADAPTER_INFO* IpAdapter = NULL;
	ULONG dwSize = 0;
	BOOL bStatus = NO_ERROR;

	IpAdapterInfo = new IP_ADAPTER_INFO[sizeof(IP_ADAPTER_INFO)];
	if (IpAdapterInfo)
	{
		if (GetAdaptersInfo(IpAdapterInfo, &dwSize) == ERROR_BUFFER_OVERFLOW)
		{
			delete[]IpAdapterInfo;
			IpAdapterInfo = new IP_ADAPTER_INFO[sizeof(IP_ADAPTER_INFO)];
			if (IpAdapterInfo)
			{
				if (GetAdaptersInfo(IpAdapterInfo, &dwSize) == NO_ERROR)
					for (IpAdapter = IpAdapterInfo; IpAdapter; IpAdapter = IpAdapter->Next)
						if (ip.s_addr == inet_addr(IpAdapter->IpAddressList.IpAddress.String))
							Address = IpAdapter->GatewayList.IpAddress.String;

				delete[]IpAdapterInfo;
			}
		}
	}

	return bStatus;
}

inline UINT16 __fastcall csum(
	UINT16* buffer,
	INT count
)
{
	ULONG sum = 0;
	while (count > 1)
	{
		sum += *buffer++;
		count -= 2;
	}

	if (count > 0)
		sum += *(UCHAR*)buffer;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (UINT16)~sum;
}

inline UINT16 __fastcall tcpsum(
	IPV4_HDR* IpHdr,
	TCP_HDR* TcpHdr
)
{
	struct PseudoTcp
	{
		ULONG src_addr;
		ULONG dst_addr;
		UCHAR zero;
		UCHAR proto;
		USHORT length;
	}PseudoTcpHeader;

	USHORT total_length = IpHdr->ip_total_lenght;
	INT TotalTcpLength = sizeof(PseudoTcp) + sizeof(TCP_HDR);
	USHORT* tcp = new USHORT[TotalTcpLength];
	UINT16 ret = 0;

	PseudoTcpHeader.src_addr = IpHdr->ip_srcaddr;
	PseudoTcpHeader.dst_addr = IpHdr->ip_destaddr;
	PseudoTcpHeader.zero = 0;
	PseudoTcpHeader.proto = IPPROTO_TCP;
	PseudoTcpHeader.length = htons(sizeof(TCP_HDR));

	if (tcp)
	{
		memcpy((UCHAR*)tcp, &PseudoTcpHeader, sizeof(PseudoTcp));
		memcpy((UCHAR*)tcp + sizeof(PseudoTcpHeader), (UCHAR*)TcpHdr, sizeof(TCP_HDR));
		ret = csum(tcp, TotalTcpLength);
	}

	delete[]tcp;
	return ret;
}
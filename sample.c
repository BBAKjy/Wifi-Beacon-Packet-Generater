#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netdb.h>
#include <string.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <time.h>

#pragma pack(push, 1)
typedef struct Radiotap{
	unsigned char Header_revision;
	unsigned char Header_pad;
	unsigned short Header_length;
	unsigned int Present_flags;
	unsigned char Flags;
	unsigned char Data_Rate;
	unsigned short Channel_freq;
	unsigned short Channel_flags;
	unsigned char Antenna_signal;
	unsigned char Antenna;
	unsigned short RX_flags; 
}Radiotap_Header;

typedef struct Beacon{
	unsigned short Frame_Control_Field;
	unsigned short Duration;
	unsigned char Receiver_address[6];
	unsigned char Transmitter_address[6];
	unsigned char BSS_Id[6];
	unsigned short seq_number;

}Beacon_Frame;

typedef struct wireless_LAN{

//----------------FIXED PARAMETERS---------------------------//

	unsigned char Timestamp[8];
	unsigned short Beacon_Interval;
	unsigned short Cap_Information;

//------------------TAGGED PARAMETERS-------------------------//

//-------------------SSID PARAMETER SET-----------------------//

	unsigned char SSID_Tag_Number;
	unsigned char SSID_Tag_length;
	unsigned char SSID[5];

//-------------------SUPPORTED RATES----------------------------//
	
	unsigned char Supported_Tag_Number;
	unsigned char Supported_Tag_length;
	unsigned char Supported_Rates[4];

//-------------------DS PARAMETER SET-----------------------------//

	unsigned char DS_Tag_Number;
	unsigned char DS_Tag_length;
	unsigned char DS_Current_Channel;

//-------------------TRAFFIC INDICATION MAP--------------------------//

	unsigned char Traffic_Tag_Number;
	unsigned char Traffic_Tag_length;
	unsigned char DTIM_count;
	unsigned char DTIM_period;
	unsigned char Bitmap_control;
	unsigned char Partial_Virtual_Bitmap;

//---------------------COUNTRY INFORMATION-----------------------------//

	unsigned char Country_Tag_Number;
	unsigned char Country_Tag_Length;
	unsigned short Country_Code;
	unsigned char Country_Environment;
	unsigned char First_Channel_Number;
	unsigned char Number_of_Channels;
	unsigned char Maximum_Transmit_Power_Level;	

//-------------------ERP INFORMATION-------------------------------//

	unsigned char ERP_Tag_Number;
	unsigned char ERP_Tag_length;
	unsigned char ERP_Information;

//--------------------EXTENDED SUPPORTED RATES-----------------------//

	unsigned char Extended_Supported_Tag_Number;
	unsigned char Extended_Supported_Tag_length;
	unsigned char Extended_Supported_Rates[8];

//----------------------------VENDOR SPECIFIC----------------------//

	unsigned char Vendor_Tag_Number;
	unsigned char Vendor_Tag_length;
	unsigned char Vendor_OUI[3];
	unsigned char Vendor_OUI_Type;
	unsigned char WME_Subtype;
	unsigned char WME_Version;
	unsigned char QoS_Info;
	unsigned char Reserved;
	
	unsigned char Ac_Parameters[16];

//-----------------HT CAPABILITIES------------------------------//

	unsigned char HT_Capabilities_Tag_Number;
	unsigned char HT_Capabilities_Tag_length;
	unsigned char HT_Capabilities_Info[2];
	unsigned char A_MPDU_Parameters;
	unsigned char Rx_Supported_Mod[16];
	unsigned short HT_Extended_Capabilities;
	unsigned char Transmit_Beam_Forming[4];
	unsigned char Antenna_Selection;

//-----------------HT INFORMATION-------------------------------//

	unsigned char HT_INFO_Tag_Number;
	unsigned char HT_INFO_Tag_length;
	unsigned char Primary_Channel;
	unsigned char HT_INFO_Subset[5];
	unsigned char INFO_Supported_Modset[16];

//-------------------QBSS LOAD ELEMENT---------------------//

	unsigned char QBSS_Tag_Number;
	unsigned char QBSS_Tag_length;
	unsigned char QBSS_Version[5];

//-----------------EXTENDED CAPACITIES-----------------//

	unsigned char EC_Tag_Number;
	unsigned char EC_Tag_length;
	unsigned char EC[8];

//-----------------VENDOR SPECIFIC--------------------//

	unsigned char V_Tag_Number;
	unsigned char V_Tag_length;
	unsigned char V_OUI[3];
	unsigned char V_Specific_Data[5];
}wireless_Header;

typedef struct Association_wireless_LAN{

//----------------FIXED PARAMETERS---------------------------//
	unsigned short Capabilities_Information;
	unsigned short Status_Code;
	unsigned short Association_ID;

//------------------TAGGED PARAMETERS-------------------------//
//-------------------SUPPORTED RATES----------------------------//
	unsigned char Supported_Tag_Number;
	unsigned char Supported_Tag_length;
	unsigned char Supported_Rates[4];

//--------------------EXTENDED SUPPORTED RATES-----------------------//
	unsigned char Extended_Supported_Tag_Number;
	unsigned char Extended_Supported_Tag_length;
	unsigned char Extended_Supported_Rates[8];

//----------------------------VENDOR SPECIFIC----------------------//
	unsigned char Vendor_Tag_Number;
	unsigned char Vendor_Tag_length;
	unsigned char Vendor_OUI[3];
	unsigned char Vendor_OUI_Type;
	unsigned char WME_Subtype;
	unsigned char WME_Version;
	unsigned char QoS_Info;
	unsigned char Reserved;
	unsigned char Ac_Parameters[16];

//-----------------HT CAPABILITIES------------------------------//
	unsigned char HT_Capabilities_Tag_Number;
	unsigned char HT_Capabilities_Tag_length;
	unsigned char HT_Capabilities_Info[2];
	unsigned char A_MPDU_Parameters;
	unsigned char Rx_Supported_Mod[16];
	unsigned short HT_Extended_Capabilities;
	unsigned char Transmit_Beam_Forming[4];
	unsigned char Antenna_Selection;

//-----------------HT INFORMATION-------------------------------//
	unsigned char HT_INFO_Tag_Number;
	unsigned char HT_INFO_Tag_length;
	unsigned char Primary_Channel;
	unsigned char HT_INFO_Subset[5];
	unsigned char INFO_Supported_Modset[16];

//-----------------VENDOR SPECIFIC--------------------//
	unsigned char V_Tag_Number;
	unsigned char V_Tag_length;
	unsigned char V_OUI[3];
	unsigned char V_Specific_Data[5];

//-----------------EXTENDED CAPACITIES-----------------//
	unsigned char EC_Tag_Number;
	unsigned char EC_Tag_length;
	unsigned char EC[8];

	
}Association_Wireless;
#pragma pack(pop)

void Set_Radiotap(Radiotap_Header * rthdr){
	rthdr->Header_revision = 0;
	rthdr->Header_pad = 0;
	rthdr->Header_length = 18;
	rthdr->Present_flags = 0x0000482e;
	rthdr->Flags = 0x10;
	rthdr->Data_Rate = 0x04;
	rthdr->Channel_freq = htons(0x6c09);
	rthdr->Channel_flags = htons(0xa000);
	rthdr->Antenna_signal = 0xb9;
	rthdr->Antenna = 0;
	rthdr->RX_flags = 0;
}

void Set_Beacon(Beacon_Frame * bfhdr){
	bfhdr->Frame_Control_Field = htons(0x8000);
	bfhdr->Duration = 0;

	memset(bfhdr->Receiver_address,0xff,sizeof(bfhdr->Receiver_address));

	bfhdr->Transmitter_address[0] = 0xf0;
	bfhdr->Transmitter_address[1] = 0xb0;
	bfhdr->Transmitter_address[2] = 0x52;
	bfhdr->Transmitter_address[3] = 0x6a;
	bfhdr->Transmitter_address[4] = 0x1f;
	bfhdr->Transmitter_address[5] = 0xbb;

	memcpy(bfhdr->BSS_Id, bfhdr->Transmitter_address, sizeof(bfhdr->Transmitter_address));

	bfhdr->seq_number = htons(0x507a);
}

void Set_wireless_LAN(wireless_Header * wlhdr, int SSID_len, unsigned char Src_SSID[]){
	
	wlhdr->Timestamp[0] = 0x44;
	wlhdr->Timestamp[1] = 0x95;
	wlhdr->Timestamp[2] = 0x7a;
	wlhdr->Timestamp[3] = 0x3b;
	wlhdr->Timestamp[4] = 0x00;
	wlhdr->Timestamp[5] = 0x00;
	wlhdr->Timestamp[6] = 0x00;
	wlhdr->Timestamp[7] = 0x00;

	wlhdr->Beacon_Interval = htons(0x6400);
	wlhdr->Cap_Information = htons(0x2104);

	wlhdr->SSID_Tag_Number = 0x00;
	wlhdr->SSID_Tag_length = SSID_len;
	wlhdr->SSID[0] = 0x59;
	wlhdr->SSID[1] = 0x55;
	wlhdr->SSID[2] = 0x2d;
	wlhdr->SSID[3] = 0x41;
	wlhdr->SSID[4] = 0x50;


	for(int i=0;i<SSID_len;i++)
		wlhdr->SSID[i] = Src_SSID[i];

	wlhdr->Supported_Tag_Number = 1;
	wlhdr->Supported_Tag_length = 4;
	wlhdr->Supported_Rates[0] = 0x82;
	wlhdr->Supported_Rates[1] = 0x84;
	wlhdr->Supported_Rates[2] = 0x8b;
	wlhdr->Supported_Rates[3] = 0x96;

	wlhdr->DS_Tag_Number = 3;
	wlhdr->DS_Tag_length = 1;
	wlhdr->DS_Current_Channel = 1;

	wlhdr->Traffic_Tag_Number = 5;
	wlhdr->Traffic_Tag_length = 4;
	wlhdr->DTIM_count = 0;
	wlhdr->DTIM_period = 1;
	wlhdr->Bitmap_control = 0;
	wlhdr->Partial_Virtual_Bitmap = 8;

	wlhdr->Country_Tag_Number = 7;
	wlhdr->Country_Tag_Length = 6;
	wlhdr->Country_Code = htons(0x4b52);
	wlhdr->Country_Environment = 0x20;
	wlhdr->First_Channel_Number = 1;
	wlhdr->Number_of_Channels = 1;
	wlhdr->Maximum_Transmit_Power_Level = 0x1b;	

	wlhdr->ERP_Tag_Number = 0x2a;
	wlhdr->ERP_Tag_length = 1;
	wlhdr->ERP_Information = 0;

	wlhdr->Extended_Supported_Tag_Number = 0x32;
	wlhdr->Extended_Supported_Tag_length = 8;
	
	wlhdr->Extended_Supported_Rates[0] = 0x0c;
	wlhdr->Extended_Supported_Rates[1] = 0x12;
	wlhdr->Extended_Supported_Rates[2] = 0x18;
	wlhdr->Extended_Supported_Rates[3] = 0x24;
	wlhdr->Extended_Supported_Rates[4] = 0x30;
	wlhdr->Extended_Supported_Rates[5] = 0x48;
	wlhdr->Extended_Supported_Rates[6] = 0x60;
	wlhdr->Extended_Supported_Rates[7] = 0x6c;

	wlhdr->Vendor_Tag_Number = 0xdd;
	wlhdr->Vendor_Tag_length = 24;
	wlhdr->Vendor_OUI[0] = 0;
	wlhdr->Vendor_OUI[1] = 0x50;
	wlhdr->Vendor_OUI[2] = 0xf2;
	wlhdr->Vendor_OUI_Type = 2;
	wlhdr->WME_Subtype = 1;
	wlhdr->WME_Version = 1;
	wlhdr->QoS_Info = 0x85;
	wlhdr->Reserved = 0;
	
	wlhdr->Ac_Parameters[0] = 0x03;
	wlhdr->Ac_Parameters[1] = 0xa4;
	wlhdr->Ac_Parameters[2] = 0x00;
	wlhdr->Ac_Parameters[3] = 0x00;
	wlhdr->Ac_Parameters[4] = 0x27;
	wlhdr->Ac_Parameters[5] = 0xa4;
	wlhdr->Ac_Parameters[6] = 0x00;
	wlhdr->Ac_Parameters[7] = 0x00;
	wlhdr->Ac_Parameters[8] = 0x42;
	wlhdr->Ac_Parameters[9] = 0x43;
	wlhdr->Ac_Parameters[10] = 0x5e;
	wlhdr->Ac_Parameters[11] = 0x00;
	wlhdr->Ac_Parameters[12] = 0x62;
	wlhdr->Ac_Parameters[13] = 0x32;
	wlhdr->Ac_Parameters[14] = 0x2f;
	wlhdr->Ac_Parameters[15] = 0x00;

	wlhdr->HT_Capabilities_Tag_Number = 0x2d;
	wlhdr->HT_Capabilities_Tag_length = 26;
	wlhdr->HT_Capabilities_Info[0] = 0x01;
	wlhdr->HT_Capabilities_Info[1] = 0xad;
	wlhdr->A_MPDU_Parameters = 3;
	
	wlhdr->Rx_Supported_Mod[0] = 0xff;
	wlhdr->Rx_Supported_Mod[1] = 0xff;

	for(int i=2;i<15;i++)
		wlhdr->Rx_Supported_Mod[i] = 0;
	
	wlhdr->HT_Extended_Capabilities = 0x0400;
	wlhdr->Transmit_Beam_Forming[0] = 0x06;
	wlhdr->Transmit_Beam_Forming[1] = 0x46;
	wlhdr->Transmit_Beam_Forming[2] = 0xe7;
	wlhdr->Transmit_Beam_Forming[3] = 0x0d;
	wlhdr->Antenna_Selection = 0;

	wlhdr->HT_INFO_Tag_Number = 61;
	wlhdr->HT_INFO_Tag_length = 22;
	wlhdr->Primary_Channel = 1;

	for(int i=0;i<5;i++)
		wlhdr->HT_INFO_Subset[i] = 0;

	for(int i=0;i<16;i++)
		wlhdr->INFO_Supported_Modset[i] = 0;

	wlhdr->QBSS_Tag_Number = 11;
	wlhdr->QBSS_Tag_length = 5;

	wlhdr->QBSS_Version[0] = 0x05;
	wlhdr->QBSS_Version[1] = 0x00;
	wlhdr->QBSS_Version[2] = 0x6a;
	wlhdr->QBSS_Version[3] = 0x00;
	wlhdr->QBSS_Version[4] = 0x00;

	wlhdr->EC_Tag_Number = 0x7f;
	wlhdr->EC_Tag_length = 8;

	for(int i=0;i<8;i++)
		wlhdr->EC[i] = 0;	

	wlhdr->V_Tag_Number = 0xdd;
	wlhdr->V_Tag_length = 8;
	wlhdr->V_OUI[0] = 0x00;
	wlhdr->V_OUI[1] = 0x13;
	wlhdr->V_OUI[2] = 0x92;
	
	wlhdr->V_Specific_Data[0] = 0x01;
	wlhdr->V_Specific_Data[1] = 0x00;
	wlhdr->V_Specific_Data[2] = 0x01;
	wlhdr->V_Specific_Data[3] = 0x05;
	wlhdr->V_Specific_Data[4] = 0x00;
}

void Set_Association_Response(Beacon_Frame * bfhdr){
	bfhdr->Frame_Control_Field = htons(0x1000);
	bfhdr->Duration = htons(0xa200);

	bfhdr->Receiver_address[0] = 0x34;
	bfhdr->Receiver_address[1] = 0xa8;
	bfhdr->Receiver_address[2] = 0xeb;
	bfhdr->Receiver_address[3] = 0xec;
	bfhdr->Receiver_address[4] = 0xe2;
	bfhdr->Receiver_address[5] = 0x64;

	bfhdr->Transmitter_address[0] = 0xf0;
	bfhdr->Transmitter_address[1] = 0xb0;
	bfhdr->Transmitter_address[2] = 0x52;
	bfhdr->Transmitter_address[3] = 0x6a;
	bfhdr->Transmitter_address[4] = 0x1f;
	bfhdr->Transmitter_address[5] = 0xbb;

	memcpy(bfhdr->BSS_Id, bfhdr->Transmitter_address, sizeof(bfhdr->Transmitter_address));

	bfhdr->seq_number = htons(0x2000);
}

void Set_Association_wireless_LAN(Association_Wireless * aw){

	aw->Capabilities_Information = 0x0421;
	aw->Status_Code = 0;
	aw->Association_ID = htons(0x01c0);

	aw->Supported_Tag_Number = 1;
	aw->Supported_Tag_length = 4;
	aw->Supported_Rates[0] = 0x82;
	aw->Supported_Rates[1] = 0x84;
	aw->Supported_Rates[2] = 0x8b;
	aw->Supported_Rates[3] = 0x0c;

	aw->Extended_Supported_Tag_Number = 0x32;
	aw->Extended_Supported_Tag_length = 8;
	aw->Extended_Supported_Rates[0] = 0x12;
	aw->Extended_Supported_Rates[1] = 0x96;
	aw->Extended_Supported_Rates[2] = 0x18;
	aw->Extended_Supported_Rates[3] = 0x24;
	aw->Extended_Supported_Rates[4] = 0x30;
	aw->Extended_Supported_Rates[5] = 0x48;
	aw->Extended_Supported_Rates[6] = 0x60;
	aw->Extended_Supported_Rates[7] = 0x6c;

	aw->Vendor_Tag_Number = 0xdd;
	aw->Vendor_Tag_length = 24;
	aw->Vendor_OUI[0] = 0x00;
	aw->Vendor_OUI[1] = 0x50;
	aw->Vendor_OUI[2] = 0xf2;
	aw->Vendor_OUI_Type = 2;
	aw->WME_Subtype = 1;
	aw->WME_Version = 1;
	aw->QoS_Info = 0x86;
	aw->Reserved = 0;
	aw->Ac_Parameters[0] = 0x03;
	aw->Ac_Parameters[1] = 0xa4;
	aw->Ac_Parameters[2] = 0x00;
	aw->Ac_Parameters[3] = 0x00;
	aw->Ac_Parameters[4] = 0x27;
	aw->Ac_Parameters[5] = 0xa4;
	aw->Ac_Parameters[6] = 0x00;
	aw->Ac_Parameters[7] = 0x00;
	aw->Ac_Parameters[8] = 0x42;
	aw->Ac_Parameters[9] = 0x43;
	aw->Ac_Parameters[10] = 0x5e;
	aw->Ac_Parameters[11] = 0x00;
	aw->Ac_Parameters[12] = 0x62;
	aw->Ac_Parameters[13] = 0x32;
	aw->Ac_Parameters[14] = 0x2f;
	aw->Ac_Parameters[15] = 0x00;

	aw->HT_Capabilities_Tag_Number = 0x2d;
	aw->HT_Capabilities_Tag_length = 0x1a;
	aw->HT_Capabilities_Info[0] = 0xad; // Exchange Value
	aw->HT_Capabilities_Info[1] = 0x01;
	aw->A_MPDU_Parameters = 3;

	for(int i=0;i<2;i++)
		aw->Rx_Supported_Mod[i] = 0xff;

	for(int i=2;i<16;i++)
		aw->Rx_Supported_Mod[i] = 0;

	aw->HT_Extended_Capabilities = 0x0400;
	aw->Transmit_Beam_Forming[0] = 0x06;
	aw->Transmit_Beam_Forming[1] = 0x46;
	aw->Transmit_Beam_Forming[2] = 0xe7;
	aw->Transmit_Beam_Forming[3] = 0x0d;
	aw->Antenna_Selection = 0;

	aw->HT_INFO_Tag_Number = 0x3d;
	aw->HT_INFO_Tag_length = 22;
	aw->Primary_Channel = 1;
	aw->HT_INFO_Subset[0] = 0;
	aw->HT_INFO_Subset[1] = 0x11;
	aw->HT_INFO_Subset[2] = 0;
	aw->HT_INFO_Subset[3] = 0;
	aw->HT_INFO_Subset[4] = 0;

	for(int i=0;i<16;i++)
		aw->INFO_Supported_Modset[i] = 0;

	aw->V_Tag_Number = 0xdd;
	aw->V_Tag_length = 8;
	aw->V_OUI[0] = 0x00;
	aw->V_OUI[1] = 0x13;
	aw->V_OUI[2] = 0x92;
	aw->V_Specific_Data[0] = 0x01;
	aw->V_Specific_Data[1] = 0x00;
	aw->V_Specific_Data[2] = 0x01;
	aw->V_Specific_Data[3] = 0x05;
	aw->V_Specific_Data[4] = 0x00;

	aw->EC_Tag_Number = 0x7f;
	aw->EC_Tag_length = 8;
	aw->EC[0] = 0x00;
	aw->EC[1] = 0x00;
	aw->EC[2] = 0x08;
	aw->EC[3] = 0x00;
	aw->EC[4] = 0x00;
	aw->EC[5] = 0x00;
	aw->EC[6] = 0x00;
	aw->EC[7] = 0x00;
}

int main(void){
	struct ifreq if_idx;
	struct sockaddr_ll socket_addr;
	memset(&socket_addr, 0, sizeof(struct sockaddr_ll));
	int socket1;

	int SSID_len = 5;
	unsigned char Src_SSID[] = {'G','O','D','J','Y'};
	unsigned char recv_buffer[1024];
	memset(recv_buffer, 0xff, sizeof(recv_buffer));
	
	unsigned char buff[1024];
	memset(buff, 0x00, sizeof(buff));

	socket1 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	strncpy(if_idx.ifr_ifrn.ifrn_name, "wlan0", IFNAMSIZ); //Select network interface
	ioctl(socket1, SIOCGIFINDEX, &if_idx);

	socket_addr.sll_family = PF_PACKET;
	socket_addr.sll_ifindex = if_idx.ifr_ifru.ifru_ivalue;		

	while(1){
		Radiotap_Header * rthdr = NULL;
		rthdr = (Radiotap_Header *)buff;
		Set_Radiotap(rthdr);
	
		Beacon_Frame * bfhdr = NULL;
		bfhdr = (Beacon_Frame *)&buff[sizeof(Radiotap_Header)];
		Set_Beacon(bfhdr);

		wireless_Header * wlhdr = NULL;
		wlhdr = (wireless_Header *)&buff[sizeof(Radiotap_Header)+sizeof(Beacon_Frame)];
		Set_wireless_LAN(wlhdr, SSID_len, Src_SSID);

		sendto(socket1, buff, sizeof(struct Radiotap)+sizeof(struct Beacon)+sizeof(struct wireless_LAN)+4, 0, (struct sockaddr *)&socket_addr, sizeof(socket_addr));
		recvfrom(socket1, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&socket_addr, sizeof(socket_addr));
		
		if(recv_buffer[18] == 0x00&&recv_buffer[19]==0x00){
			
			memset(buff,0,sizeof(buff));			

			rthdr = (Radiotap_Header *)buff;
			Set_Radiotap(rthdr);

			bfhdr = (Beacon_Frame *)&buff[sizeof(Radiotap_Header)];
			Set_Association_Response(bfhdr);

			Association_Wireless * aw = NULL;
			aw = (Association_Wireless *)&buff[sizeof(Radiotap_Header)+sizeof(Beacon_Frame) ];
			Set_Association_wireless_LAN(aw);

			sendto(socket1, buff, sizeof(struct Radiotap)+sizeof(struct Beacon)+sizeof(struct Association_wireless_LAN)+4, 0, (struct sockaddr *)&socket_addr, sizeof(socket_addr));
		}


		memset(recv_buffer, 0xff, sizeof(recv_buffer));
	}
	

}

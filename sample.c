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
	unsigned int Frame_check_seq;

}Beacon_Frame;

typedef struct wireless_LAN{

//----------------FIXED PARAMETERS---------------------------//

	unsigned long long int Timestamp;
	unsigned short Beacon_Interval;
	unsigned short Cap_Information;

//------------------TAGGED PARAMETERS-------------------------//

//-------------------SSID PARAMETER SET-----------------------//

	unsigned char SSID_Tag_Number;
	unsigned char SSID_Tag_length;
	unsigned char *SSID;

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
	unsigned char Country_Code;
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
	unsigned char *Extended_Supported_Rates;

//----------------------------VENDOR SPECIFIC----------------------//

	unsigned char Vendor_Tag_Number;
	unsigned char Vendor_Tag_length;
	unsigned char Vendor_OUI[3];
	unsigned char Vendor_OUI_Type;
	unsigned char Type;
	unsigned char WME_Subtype;
	unsigned char WME_Version;
	unsigned char QoS_Info;
	unsigned char Reserved;
	
	unsigned char Ac_Parameters[16];

//-----------------HT CAPABILITIES------------------------------//

	unsigned char HT_Capabilities_Tag_Number;
	unsigned char HT_Capabilities_Tag_length;
	unsigned short HT_Capabilities_Info;
	unsigned char A_MPDU_Parameters;
	unsigned char Rx_Supported_Mod[16];
	unsigned short HT_Extended_Capabilities;
	unsigned int Transmit_Beam_Forming;
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
	unsigned short Station_Count;
	unsigned char Channel_Utilization;
	unsigned short Available_Admission_Capacity;

//-----------------EXTENDED CAPACITIES-----------------//

	unsigned char EC_Tag_Number;
	unsigned char EC_Tag_length;
	unsigned char EC[8];

//-----------------VENDOR SPECIFIC--------------------//

	unsigned char V_Tag_Number;
	unsigned char V_Tag_length;
	unsigned char V_OUI[3];
	unsigned char V_Specific_Data[5];
}wiereless_HEADER;

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
	bfhdr->Transmitter_address[5] = 0xa8;

	memcpy(bfhdr->BSS_Id, bfhdr->Transmitter_address, sizeof(bfhdr->Transmitter_address));

	bfhdr->seq_number = htons(0x507a);
	bfhdr->Frame_check_seq = 0x7dd03033;
}

int main(void){
	struct ifreq if_idx;
	struct sockaddr_ll socket_addr;
	memset(&socket_addr, 0, sizeof(struct sockaddr_ll));
	int socket1;
	
	unsigned char buff[150];
	memset(buff, 0, sizeof(buff));

	Radiotap_Header * rthdr = NULL;
	rthdr = (Radiotap_Header *)buff;
	Set_Radiotap(rthdr);

	Beacon_Frame * bfhdr = NULL;
	bfhdr = (Beacon_Frame *)&buff[sizeof(Radiotap_Header)-2];
	Set_Beacon(bfhdr);



	socket1 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	strncpy(if_idx.ifr_ifrn.ifrn_name, "wlan0", IFNAMSIZ); //Select network interface
	ioctl(socket1, SIOCGIFINDEX, &if_idx);

	socket_addr.sll_family = PF_PACKET;
	socket_addr.sll_ifindex = if_idx.ifr_ifru.ifru_ivalue;

	while(1){
		sendto(socket1, buff, sizeof(struct Radiotap)+sizeof(struct Beacon), 0, (struct sockaddr *)&socket_addr, sizeof(socket_addr));
		sleep(1);
	}
	

}

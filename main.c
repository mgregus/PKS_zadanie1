#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>


/* run this program using the console pauser or add your own getch, system("pause") or input loop */


int main(int argc, char *argv[]) {
	
	//error sizedefined in the lib
	char chyba_packet_suboru[PCAP_ERRBUF_SIZE];
	
	
	//nacitanie nazvu .pcap suboru
	char filepath[200] = "pcap/";
	char *filename;
	filename = malloc(200);
	printf("zadajde nazov .pcap suboru\n");
	scanf("%s",filename);
	int filenamelength = 0;
	while(filename[filenamelength])
		filenamelength++;
	strncat(filepath, filename, filenamelength);
	//printf("%s ",filepath);
	
	struct pcap_pkthdr *hlavicka_packetu;
	const u_char * 	data_packetu;
	pcap_t *pcap_subor;	
	pcap_subor = pcap_open_offline(filepath, chyba_packet_suboru);
	
	if(pcap_subor == NULL){
		printf("Chyba pri otvarani packet suboru: %s\n",chyba_packet_suboru);
		return 1;
	}
	
	int porcisloramca = 0;
	while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1){
		porcisloramca++;
		printf("ramec: %d\n",porcisloramca);
		printf("dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
		printf("dlzka prenasana po mediu - %d B\n\n",hlavicka_packetu->len);
	}
	
	pcap_close(pcap_subor);
	return 0;
}


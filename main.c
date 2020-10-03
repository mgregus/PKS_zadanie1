#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>


/* run this program using the console pauser or add your own getch, system("pause") or input loop */

typedef struct Ethernetframe{
	char Smacad[6];
	char Dmacad[6];
	char type[4];
}Ethernet;

int dlzka_paketu_po_mediu(int apilength){
	int medialength = 0;
		
	if(apilength >= 60)
		medialength = apilength + 4;
	
	else
		medialength = 64;
	
	return medialength;
}

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
	int modvypisu = 0;
	
	//pomocne .txt subory
	
	FILE *output;
	output = fopen("output.txt","w");
	
	//vyber modu vypisu
	printf("zadajte mod vypisu: \n");
	scanf("%d",&modvypisu);
	
	//pcap struktury
	struct pcap_pkthdr *hlavicka_packetu;
	const u_char *data_packetu;
	pcap_t *pcap_subor;	
	pcap_subor = pcap_open_offline(filepath, chyba_packet_suboru);
	
	//otvaranie potrebnych suborov
	if(pcap_subor == NULL){
		printf("Chyba pri otvarani packet suboru: %s\n",chyba_packet_suboru);
		return 1;
	}
	
	if(modvypisu == 1){
	
		int porcisloramca = 0;
		while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1){
			porcisloramca++;
			fprintf(output,"ramec: %d\n",porcisloramca);
			fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
			fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
		
			//vypis ramca
			int it = 0;
			while(it < hlavicka_packetu->len){
				if(it % 8 == 0 && it > 0)
					fprintf(output,"  ");
				if(it % 16 == 0)
					fprintf(output,"\n");
				fprintf(output,"%.2x ",data_packetu[it++]);
			}
			fprintf(output,"\n\n");
		}
	
	}
	
	fclose(output);
	pcap_close(pcap_subor);
	return 0;
}


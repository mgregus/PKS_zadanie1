#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <pcap.h>
#include <string.h>


/* run this program using the console pauser or add your own getch, system("pause") or input loop */


int dlzka_paketu_po_mediu(int apilength){
	int medialength = 0;
		
	if(apilength >= 60)
		medialength = apilength + 4;
	
	else
		medialength = 64;
	
	return medialength;
}

u_char *copyuchar(u_char *source, int n){
	int i;
	u_char *dest;
	dest = malloc(n*sizeof(u_char));
	for(i = 0; i < n; i++){
		printf("%.2x ",source[i]);
		dest[i] = source[i];
	}	

	return dest;
}

u_short hex_to_dec(u_char *x){
	u_short decimal = *(u_short*)x;
	return decimal = (decimal >> 8) | ((decimal & 255) << 8);;	
}

int main(int argc, char *argv[]) {
	
	//error sizedefined in the lib
	char chyba_packet_suboru[PCAP_ERRBUF_SIZE];
	
	//nacitanie nazvu .pcap suboru
	char filepath[200] = "pcap/";
	char *filename;
	u_char *L2protokol;
	L2protokol = malloc(2*sizeof(u_char));
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
		while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1/* && porcisloramca < 5*/){
			porcisloramca++;
			fprintf(output,"ramec: %d\n",porcisloramca);
			fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
			fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
			
			//printf("decimal: %d\n",hex_to_dec("8c6F",4));
			
			//zistenie typu L2 ramca
			int pom = 0;
			int i;
			for(i = 12; i < 14; i++)
				L2protokol[pom++] = data_packetu[i]; 
			
			//Ramec L2 vrstvy je Ethernet
			if(hex_to_dec(L2protokol) > 1500){
				fprintf(output,"Ethernet II\n");
			}			
			//Ramec L2 vrstvy je IEEE 802.3
			else{
				fprintf(output,"IEEE 802.3\n");
			}
			
			//zistenie MAC adries
			fprintf(output,"Cielová MAC adresa: ");
			for(i = 0 ; i < 6; i++){
				fprintf(output,"%.2x ",data_packetu[i]);
			}
			fprintf(output,"\n");
			fprintf(output,"Zdrojová MAC adresa: ");
			for(i = 6 ; i < 12; i++){
				fprintf(output,"%.2x ",data_packetu[i]);
			}
			fprintf(output,"\n");
			
			
				
				
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


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <pcap.h>
#include <string.h>


/* run this program using the console pauser or add your own getch, system("pause") or input loop */

typedef struct Ethernet{
	u_char Dmac[6];
	u_char Smac[6];
	u_char type[2];
}Ethernet;

typedef struct IEEEraw{
	u_char Dmac[6];
	u_char Smac[6];
	u_char len[2];
	u_char ipx[3];
}IEEEraw;

typedef struct IEEEllc{
	u_char Dmac[6];
	u_char Smac[6];
	u_char len[2];
	u_char dsap[1];
	u_char ssap[1];
	u_char cont[1];
}IEEEllc;

typedef struct IEEEsnap{
	u_char Dmac[6];
	u_char Smac[6];
	u_char len[2];
	u_char dsap[1];
	u_char ssap[1];
	u_char cont[1];
	u_char vc[3];
	u_char type[2];
}IEEEsnap;

typedef struct IPv4{
	u_char ihlv[1];
	u_char tos[1];
	u_char length[2];
	u_char nic[2];
	u_char fragoff[2];
	u_char ttl[1];
	u_char protocol[1];
	u_char checksum[2];
	u_char sourceip[4];
	u_char destip[4];
}IPv4;

typedef struct IPv6{
	u_char vtraffic[4];
	u_char payload[2];
	u_char protocol[1];
	u_char ttl[1];
	u_char sourceip[16];
	u_char destip[16];
}IPv6;

typedef struct ARP{
	u_char nic[6];
	u_char reqrep[2];
	u_char srcmac[6];
	u_char srcip[4];
	u_char tmac[6];
	u_char tip[4];
}ARP;

typedef struct UZLY{
	u_char adresa[4];
	int prijatych;
	struct UZLY *next;
}UZLY;

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
		//printf("%.2x ",source[i]);
		dest[i] = source[i];
	}	

	return dest;
}


//postupnost bajtov zmeni na desiatkove cislo, funguje len do 4B
int hodnota(u_char *pole, int n){
	int i,j,iter;
	iter = 0;
	i = 0;
	
	for(iter = 0; iter < n ; iter++){
		i = i << 8;
		i += (int)pole[iter];
	}
	
	return i;
}


void vypisMacadries(Ethernet *pt, FILE *output){
			
			int i;
			
			fprintf(output,"Cielová MAC adresa: ");
			for(i = 0; i < 6; i++)
			fprintf(output,"%.2x ",pt->Dmac[i]);
			fprintf(output,"\n");
			
			fprintf(output,"Zdrojová MAC adresa: ");
			for(i = 0; i < 6; i++)
			fprintf(output,"%.2x ",pt->Smac[i]);
			fprintf(output,"\n");			
}

void vypisIpadries(IPv4 *pt, FILE *output){
			int i;			
			fprintf(output,"Zdrojová Ip adresa: ");
			for(i = 0; i < 4; i++){
				if(i == 3)
					fprintf(output,"%d",pt->sourceip[i]);
				else 	
					fprintf(output,"%d.",pt->sourceip[i]);
				}
			fprintf(output,"\n");
			
			fprintf(output,"Cielová Ip adresa: ");
			for(i = 0; i < 4; i++){
				if(i == 3)
					fprintf(output,"%d",pt->destip[i]);
				else 	
					fprintf(output,"%d.",pt->destip[i]);
				}
			fprintf(output,"\n");			
			
}

void vypisIpadriesuzlov(UZLY *pt, FILE *output){
		
			int i;			
		
			for(i = 0; i < 4; i++){
				if(i == 3)
					fprintf(output,"%d",pt->adresa[i]);
				else 	
					fprintf(output,"%d.",pt->adresa[i]);
				}
			fprintf(output,"\n");
					
}


//interpretuje nazov protokolu/portu z externeho suboru
char *nazov(int vstup, FILE *subor){
	rewind(subor);
	char *name;
	char *pom;
	name = malloc(200*sizeof(char));
	pom = malloc(200*sizeof(char));
	int count = 0; 
	
	char c;
	char found = 0;
	int hodnotasth;
    
	while((c=getc(subor))!= EOF){
        if(isdigit(c) && c == '0'){
        	ungetc(c,subor);
        	getc(subor);
        	fscanf(subor,"%x",&hodnotasth);
     		
			    	
        	if(hodnotasth == vstup){
        		fscanf(subor,"%[^\n]s",name);
        		
        		/*//check pre porty aj nazov
				if(isdigit(name[0])){
        			
					fscanf(subor,"%s",pom);
        			
					while(pom[count++] != 0);
        			strncat(name," \0",1);
        			strncat(name, pom,count);
        			free(pom);
				}
				*/
        		found = 1; 
        		break;
			}
		}
    }
	name = name + 1;
	if(found == 1)
		return name;
	return "dany zaznam nie je v externom subore\0";
}


int main(int argc, char *argv[]) {
	
	//error sizedefined in the lib
	char chyba_packet_suboru[PCAP_ERRBUF_SIZE];
	
	//nacitanie nazvu .pcap suboru
	char filepath[200] = "pcap/";
	char *filename;
	char nazovvypisu[100];
	u_char *L2protokol;
	L2protokol = malloc(2*sizeof(u_char));
	filename = malloc(200);
	int filenamelength = 0;
	//printf("%s ",filepath);
	int modvypisu = 0;
	int pocetvypisov = 0;
	//***********************************************************************************
	
	//pomocne .txt subory
	FILE *output;
	FILE *protokoly;
	protokoly = fopen("protokoly.txt","r");
	if(protokoly == NULL){
		printf("neda sa otvorit externy subor\n");
		return 2;
	}
	//***********************************************************************************
	

	
	//pcap struktury
	struct pcap_pkthdr *hlavicka_packetu;
	const u_char *data_packetu;
	pcap_t *pcap_subor;	
	//***********************************************************************************
	
	//pomocne premmenne
	u_char *pom;
	int decimalvalue;
	char *nazovsth;
	int type;
	int maxprijatych;
	int porcisloramca = 0;
	char aktualizovane;
	//***********************************************************************************
	
	
	//l2 struktury
	Ethernet *ethernet = malloc(sizeof(Ethernet));
	IEEEraw *ieee = malloc(sizeof(IEEEraw));
	IEEEllc *ieeellc = malloc(sizeof(IEEEllc));
	IEEEsnap *ieeesnap = malloc(sizeof(IEEEsnap));
	//***********************************************************************************
	
	//l3struktury
	IPv6 *sestka = malloc(sizeof(IPv6));
	ARP *arp = malloc(sizeof(ARP));
	IPv4 *stvorka = malloc(sizeof(IPv4));
	UZLY *uzly = NULL;
	UZLY *uzlypomocny = NULL;
	UZLY *uzlymax = NULL;
	
	//***********************************************************************************
	
	
	
	//loop to keep analyzing new files
	while(modvypisu != -1){
	
		sprintf(filepath,"pcap/");
		filenamelength = 0;
		printf("zadajde nazov .pcap suboru\n");
		scanf("%s",filename);
		
		while(filename[filenamelength])
			filenamelength++;
		
		strncat(filepath, filename, filenamelength);
		
		pcap_subor = pcap_open_offline(filepath, chyba_packet_suboru);
		
		
		//otvaranie potrebnych suborov
		if(pcap_subor == NULL){
			printf("Chyba pri otvarani packet suboru: %s\n",chyba_packet_suboru);
			printf("zadajte mod vypisu: \n");
			scanf("%d",&modvypisu);
			if(modvypisu == -1){	
			break;
			}
			continue;
		}
	
		pocetvypisov++;
		sprintf(nazovvypisu,"output%d.txt",pocetvypisov);
		output = fopen(nazovvypisu,"w");
		
		//vyber modu vypisu
		printf("zadajte mod vypisu: \n");
		scanf("%d",&modvypisu);
		
		if(modvypisu == -1){
			fclose(output);
			pcap_close(pcap_subor);			
			break;
		}
		
			//***********************************************************************************

		else if(modvypisu == 1){
			
				porcisloramca = 0;
				while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& porcisloramca < 5*/){
					type = 0;
					porcisloramca++;
					
					fprintf(output,"ramec: %d\n",porcisloramca);
					fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
					fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
					
					
					//zistenie typu L2 ramca
					ethernet = (Ethernet*)(data_packetu);
					ieee = (IEEEraw*)(data_packetu);
					ieeellc = (IEEEllc*)(data_packetu);
					ieeesnap = ((IEEEsnap*)data_packetu);
					
					
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar((u_char*)data_packetu+12, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
					
						
					if(decimalvalue > 1500){
						fprintf(output,"Ethernet II\n");
						type = decimalvalue;
					}
					else{
						
						fprintf(output,"IEEE 802.3 ");
						pom = copyuchar(ieee->ipx,1);	
						decimalvalue = hodnota(pom, 1);	
						free(pom);
						
						//raw/lcc/llc+snap if splnene tak je to raw
						if(decimalvalue == 255){
							
							fprintf(output,"- Raw\n");
							vypisMacadries(ethernet,output);
							nazovsth = nazov(decimalvalue,protokoly);
							fprintf(output,"%s\n",nazovsth);
						
						}//llc/llc+snap
						else{
							
							pom = copyuchar(ieeellc->ssap,1);
							decimalvalue = hodnota(pom, 1);	
							free(pom);
							
							
							//ma llc aj sna
							if(decimalvalue == 170){
								fprintf(output," s LLC a SNAP\n");
								pom = copyuchar(ieeesnap->type,2);	
								decimalvalue = hodnota(pom, 2);
								free(pom);
								vypisMacadries(ethernet,output);	
								nazovsth = nazov(decimalvalue,protokoly);
								fprintf(output,"%s\n",nazovsth);
							}//ma llc
							else{
								fprintf(output," s LLC\n");
								vypisMacadries(ethernet,output);	
								pom = copyuchar(ieeellc->ssap,1);
								decimalvalue = hodnota(pom, 1);	
								free(pom);
								nazovsth = nazov(decimalvalue,protokoly);
								fprintf(output,"%s\n",nazovsth);
							}					
						}
					
					
					}
					
					
					
					
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
						vypisMacadries(ethernet,output);	
						nazovsth = nazov(type,protokoly);
						fprintf(output,"%s\n",nazovsth);
						/*
						spytat sa na toto na cviceni????
						if(type == 800){
						IPv4 = (ipv4*)(data_packetu+sizeof(ethernet));
						}
						*/
					}
					
					
						
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
		
		//***********************************************************************************
		//***********************************************************************************

		//aj Ip adresy uzlov a uzla ktori najviac prijal
		else if(modvypisu == 3){
			
				porcisloramca = 0;
				maxprijatych = 0;
				uzlypomocny = NULL;
				uzly = NULL;
				uzlymax = NULL;
				while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& porcisloramca < 5*/){
					type = 0;
					aktualizovane = 0;
					porcisloramca++;
					
					fprintf(output,"ramec: %d\n",porcisloramca);
					fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
					fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
					
					
					//zistenie typu L2 ramca
					ethernet = (Ethernet*)(data_packetu);
					ieee = (IEEEraw*)(data_packetu);
					ieeellc = (IEEEllc*)(data_packetu);
					ieeesnap = ((IEEEsnap*)data_packetu);
					
					
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar((u_char*)data_packetu+12, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
						
					if(decimalvalue > 1500){
						fprintf(output,"Ethernet II\n");
						type = decimalvalue;
					}
					else{
						
						fprintf(output,"IEEE 802.3 ");
						pom = copyuchar(ieee->ipx,1);	
						decimalvalue = hodnota(pom, 1);	
						free(pom);
						
						//raw/lcc/llc+snap if splnene tak je to raw
						if(decimalvalue == 255){
							
							fprintf(output,"- Raw\n");
							vypisMacadries(ethernet,output);
							nazovsth = nazov(decimalvalue,protokoly);
							fprintf(output,"%s\n",nazovsth);
						
						}//llc/llc+snap
						else{
							
							pom = copyuchar(ieeellc->ssap,1);
							decimalvalue = hodnota(pom, 1);	
							free(pom);
							
							//ma llc aj sna
							if(decimalvalue == 170){
								fprintf(output," s LLC a SNAP\n");
								pom = copyuchar(ieeesnap->type,2);	
								decimalvalue = hodnota(pom, 2);
								free(pom);
								vypisMacadries(ethernet,output);	
								nazovsth = nazov(decimalvalue,protokoly);
								fprintf(output,"%s\n",nazovsth);
							}//ma llc
							else{
								fprintf(output," s LLC\n");
								vypisMacadries(ethernet,output);	
								pom = copyuchar(ieeellc->ssap,1);
								decimalvalue = hodnota(pom, 1);	
								free(pom);
								nazovsth = nazov(decimalvalue,protokoly);
								fprintf(output,"%s\n",nazovsth);
							}					
						}
					
					
					}
					
					
					
					
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
						vypisMacadries(ethernet,output);	
						nazovsth = nazov(type,protokoly);
						fprintf(output,"%s\n",nazovsth);
						
						//spytat sa na toto????
						
						if(type == 2048){
						
							stvorka = (IPv4*)(data_packetu+sizeof(Ethernet));
							vypisIpadries(stvorka, output);
							
							//pridanie na zaciatok sp zoznamu
							if(uzly == NULL){
								uzly = malloc(sizeof(UZLY));
								uzly->prijatych = 1;
								strcpy((char*)uzly->adresa,(char*)stvorka->destip);
								uzly->next = NULL;
							}
							//pridanie do sp zoznamu alebo aktualizacia zaznamu
							else if(uzly != NULL){
								
								uzlypomocny = uzly;
								uzlymax = NULL;
								
								while(uzlypomocny != NULL){
									if(strcmp((char*)uzlypomocny->adresa,(char*)stvorka->destip) == 0){
										uzlypomocny->prijatych += 1;
										aktualizovane = 1;
									}
									uzlymax = uzlypomocny;
									uzlypomocny = uzlypomocny->next;										
								}
								
								if(aktualizovane == 0){
									uzlymax->next = malloc(sizeof(UZLY));
									uzlymax = uzlymax->next;
									uzlymax->prijatych = 1;
									strcpy((char*)uzlymax->adresa,(char*)stvorka->destip);
									uzlymax->next = NULL;
								}								
								
							}
							
						}
						
					}
					
					
						
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
				
				//vypis adries uzlov
				fprintf(output,"Zoznam IPv4 adries vsetkych prijimajucich uzlov: \n");
				//prebehnutie celeho zoznamu
				uzlypomocny = uzly;
				
				while(uzlypomocny != NULL){
					vypisIpadriesuzlov(uzlypomocny,output);
					uzlypomocny = uzlypomocny->next;				
				}
				
				//vypis najpocetnejsieho
				fprintf(output,"Adresa uzla s najväèším poètom odoslaných paketov: \n");
				
				uzlypomocny = uzly;
				uzlymax = uzly;
				
				while(uzlypomocny != NULL){
					
					if(uzlypomocny->prijatych > uzlymax->prijatych){
					
						uzlymax = uzlypomocny;
					
					}
					
					uzlypomocny = uzlypomocny->next;				
				}
				
				int i;
				for(i = 0; i < 4; i++){
					if(i == 3)
						fprintf(output,"%d",uzlymax->adresa[i]);
					else 	
						fprintf(output,"%d.",uzlymax->adresa[i]);
				
				}
				
				fprintf(output,"\t %d packetov\n",uzlymax->prijatych);
				
				//uvolnenie celeho zoznamu
			
					
			
		//***********************************************************************************
		//***********************************************************************************
			
		
			
		}
	
		fclose(output);
		pcap_close(pcap_subor);
	}
	//***********************************************************************************
	
	

	return 0;
}


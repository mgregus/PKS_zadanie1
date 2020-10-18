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



typedef struct IPv4{
	u_char ihlv[1];
	u_char protocol[1];
	u_char sourceip[4];
	u_char destip[4];
}IPv4;

typedef struct IPv6{
	u_char protocol[1];
	u_char sourceip[16];
	u_char destip[16];
}IPv6;

typedef struct ARP{
	//request /reply
	u_char operation[2];
	
	//request unicast mac of sender
	//reply unicast mac of reciever which was unknown
	u_char sendermac[6];
	u_char senderip[4];
	
	//request broadcast ff:ff
	//reply unicast address
	u_char targetmac[6];
	u_char targetip[4];
}ARP;


typedef struct TCP{
	u_char sourceport[2];
	u_char destport[2];
	u_char flag[1];
}TCP;

typedef struct ICMP{
	u_char type[1];
	u_char code[1];
}ICMP;

typedef struct UDP{
	u_char sourceport[2];
	u_char destport[2];
}UDP;


typedef struct UZLY{
	u_char *adresa;
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

void cpchar(u_char *source,u_char *dest, int n){
	int i;
	
	for(i = 0; i < n; i++){
		dest[i] = source[i];
	}	
	
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
			
			fprintf(output,"Cielov� MAC adresa: ");
			for(i = 0; i < 6; i++)
			fprintf(output,"%.2x ",pt->Dmac[i]);
			fprintf(output,"\n");
			
			fprintf(output,"Zdrojov� MAC adresa: ");
			for(i = 0; i < 6; i++)
			fprintf(output,"%.2x ",pt->Smac[i]);
			fprintf(output,"\n");			
}

void vypisIpadriesIP(IPv4 *pt, FILE *output){
			int i;			
			fprintf(output,"Zdrojov� Ip adresa: ");
			for(i = 0; i < 4; i++){
				if(i == 3)
					fprintf(output,"%d",pt->sourceip[i]);
				else 	
					fprintf(output,"%d.",pt->sourceip[i]);
				}
			fprintf(output,"\n");
			
			fprintf(output,"Cielov� Ip adresa: ");
			for(i = 0; i < 4; i++){
				if(i == 3)
					fprintf(output,"%d",pt->destip[i]);
				else 	
					fprintf(output,"%d.",pt->destip[i]);
				}
			fprintf(output,"\n");			
			
}

void vypisIpadriesIPv6(IPv6 *pt, FILE *output){
			int i;			
			fprintf(output,"Zdrojov� Ipv6 adresa: ");
			for(i = 0; i < 16; i++){
				if(i != 0 && i%2 == 0){
					fprintf(output,":");
				}
				if(pt->sourceip[i] == 0)
					fprintf(output,"%x0",pt->sourceip[i]);
				else if(pt->sourceip[i] <= 15)
					fprintf(output,"0%x",pt->sourceip[i]);
				else
					fprintf(output,"%x",pt->sourceip[i]);
			}
			fprintf(output,"\n");
			
			fprintf(output,"Cielov� Ipv6 adresa: ");
			for(i = 0; i < 16; i++){
				if(i != 0 && i%2 == 0){
					fprintf(output,":");
				}
				if(pt->destip[i] == 0)
					fprintf(output,"%x0",pt->destip[i]);
				else if(pt->destip[i] <= 15)
					fprintf(output,"0%x",pt->destip[i]);
				else
					fprintf(output,"%x",pt->destip[i]);
			}
			fprintf(output,"\n");			
			
}

void vypisIpadriesARP(ARP *pt, FILE *output){
			int i;			
			fprintf(output,"Sender Ip adresa: ");
			for(i = 0; i < 4; i++){
				if(i == 3)
					fprintf(output,"%d",pt->senderip[i]);
				else 	
					fprintf(output,"%d.",pt->senderip[i]);
				}
			fprintf(output,"\n");
			
			fprintf(output,"Target Ip adresa: ");
			for(i = 0; i < 4; i++){
				if(i == 3)
					fprintf(output,"%d",pt->targetip[i]);
				else 	
					fprintf(output,"%d.",pt->targetip[i]);
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
	name = malloc(200*sizeof(char));
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
        		found = 1; 
        		break;
			}
		}
    }
    //odstranenie medzeri
	name = name + 1;
	if(found == 1)
		return name;
	return "dany zaznam nie je v externom subore\0";
}


char *nazovicmp(int type, int code, FILE *subor){
	rewind(subor);
	char *name;
	name = malloc(200*sizeof(char));
	
	char c;
	char found = 0;
	int hodnotasth;
	int hodnatasth2;    
	printf("hladane %d %d \n",type,code);
	while((c=getc(subor))!= EOF){
        if(isdigit(c)){
        	ungetc(c,subor);
        	fscanf(subor,"%d",&hodnotasth);
     		    	
        	if(hodnotasth == type){
        		found = 1;
        		if((fscanf(subor,"%d",&hodnatasth2)) == 1){
        			printf("code:%d code %d\n",hodnatasth2,code);
					if(hodnatasth2 == code){
						fscanf(subor,"%[^\n]s",name);
						return name;
					}
				}
        		else{
				fscanf(subor,"%[^\n]s",name);
				return name;
				}
			}
		}
    }
    //odstranenie medzeri
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
	FILE *messages;
	protokoly = fopen("protokoly.txt","r");
	if(protokoly == NULL){
		printf("neda sa otvorit externy subor protokoly\n");
		return 2;
	}
	messages = fopen("messages.txt","r");
	if(protokoly == NULL){
		printf("neda sa otvorit externy subor messages\n");
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
	int zport,cport;				
	int IHL;
	int maxprijatych;
	int porcisloramca = 0;
	int port;
	int pocet_komunikacii;
	int vypisanych_komunikacii;
	int pole_komunikacii[4500] = {-1};
	int private_port;
	u_int flag;
	int uplna, neuplna;
	char zaznamenane;
	char aktualizovane;
	char rovnake;
	//***********************************************************************************
	
	
	//l2 struktury
	Ethernet *ethernet = malloc(sizeof(Ethernet));
	//***********************************************************************************
	
	//l3struktury
	IPv6 *sestka = malloc(sizeof(IPv6));
	ARP *arp = malloc(sizeof(ARP));
	IPv4 *stvorka = malloc(sizeof(IPv4));
	UZLY *uzly = NULL;
	UZLY *uzlypomocny = NULL;
	UZLY *uzlymax = NULL;
	
	//***********************************************************************************
	
	//L4 struktury
	UDP *udp = malloc(sizeof(UDP));
	TCP *tcp = malloc(sizeof(TCP));
	ICMP *icmp = malloc(sizeof(ICMP));
	
	//***********************************************************************************
	printf("vypis bodov 1-3 vratane cisla portu a protokolu app. vrstvy zadajte 1-3\n");
	printf("vypis bodu 4a) HTTP zadajte 4\n");
	printf("vypis bodu 4b) HTTPs zadajte 5\n");
	printf("vypis bodu 4c) TELNET zadajte 6\n");
	printf("vypis bodu 4d) SSH zadajte 7\n");
	printf("vypis bodu 4e) FTP riadiace zadajte 8\n");
	printf("vypis bodu 4f) FTP datove zadajte 9\n");
	printf("vypis bodu 4g) TFTP zadajte 10\n");
	printf("vypis bodu 4h) ICMP zadajte 11\n");
	printf("vypis bodu 4i) ARP zadajte 12\n\n");
	
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

		else if(modvypisu >= 1 && modvypisu <= 3){
			
				porcisloramca = 0;
				while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& /*porcisloramca < 10*/){
					type = 0;
					porcisloramca++;
					
					fprintf(output,"ramec: %d\n",porcisloramca);
					fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
					fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
					
					
					//zistenie typu L2 ramca
					cpchar((u_char*)data_packetu,ethernet->Dmac,6);
					cpchar((u_char*)(data_packetu+6),ethernet->Smac,6);
					cpchar((u_char*)data_packetu+12,ethernet->type,2);
					
					
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar(ethernet->type, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
					
						
					if(decimalvalue > 1500){
						fprintf(output,"Ethernet II\n");
						type = decimalvalue;
					}
					else{
						
						fprintf(output,"IEEE 802.3 ");
						pom = copyuchar((u_char*)data_packetu+15,1);	
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
							
							pom = copyuchar((u_char*)data_packetu+15,1);
							decimalvalue = hodnota(pom, 1);	
							free(pom);
							
							
							//ma llc aj snap
							if(decimalvalue == 170){
								fprintf(output," s LLC a SNAP\n");
								nazovsth = nazov(decimalvalue,protokoly);
								fprintf(output,"SSAP: %s\n",nazovsth);
								pom = copyuchar((u_char*)data_packetu+20,2);	
								decimalvalue = hodnota(pom, 2);
								free(pom);
								vypisMacadries(ethernet,output);	
								nazovsth = nazov(decimalvalue,protokoly);
								fprintf(output,"Ether type: %s\n",nazovsth);
							}//ma llc
							else{
								fprintf(output," s LLC\n");
								vypisMacadries(ethernet,output);	
								pom = copyuchar((u_char*)data_packetu+15,1);
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
						
						//ipv4
						if(type == 2048){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+14,stvorka->ihlv,1);
							cpchar((u_char*)data_packetu+23,stvorka->protocol,1);
							cpchar((u_char*)data_packetu+26,stvorka->sourceip,4);
							cpchar((u_char*)data_packetu+30,stvorka->destip,4);
							vypisIpadriesIP(stvorka, output);
							decimalvalue = hodnota(stvorka->protocol,1);
							nazovsth = nazov(decimalvalue,protokoly);
							fprintf(output,"%s\n",nazovsth);
							
							
							//pridanie na zaciatok sp zoznamu
							if(uzly == NULL){
								uzly = malloc(sizeof(UZLY));
								uzly->prijatych = 1;
								uzly->adresa = malloc(4*sizeof(u_char));
								cpchar(stvorka->destip,uzly->adresa,4);
								uzly->next = NULL;
							}
							//pridanie do sp zoznamu alebo aktualizacia zaznamu
							else if(uzly != NULL){
								uzlypomocny = uzly;
								uzlymax = NULL;
								aktualizovane = 0;
								
								while(uzlypomocny != NULL && aktualizovane != 1){
									rovnake = 1;
									
									int i;
									for(i = 0; i < 4; i++){
										if(uzlypomocny->adresa[i] != stvorka->destip[i]){
											rovnake = 0;
										}
											
									}
										
									if(rovnake == 1){
										uzlypomocny->prijatych += 1;
										aktualizovane = 1;
									}
									
									uzlymax = uzlypomocny;
									uzlypomocny = uzlypomocny->next;										
								}
								
								if(aktualizovane == 0){
									uzlymax->next = malloc(sizeof(UZLY));
									uzlymax = uzlymax->next;
									uzlymax->adresa = malloc(4*sizeof(u_char));
									uzlymax->prijatych = 1;
									cpchar(stvorka->destip,uzlymax->adresa,4);
									uzlymax->next = NULL;
								}								
								
							}
												
							//vypocet IHL a teda kolko je dlzka celej IPv4 hlavicky
							decimalvalue = hodnota(stvorka->ihlv,1);
							IHL = decimalvalue;
							IHL = IHL << 28;
							IHL = IHL >> 28; 
							IHL = IHL * 4;
							//printf("%d\n",IHL);
							
							//analyzovanie vnoreneho protokolu TCP/UDP a adekvatny vypis portu
							decimalvalue = hodnota(stvorka->protocol,1);
		
										
							if(decimalvalue == 6){
								cpchar((u_char*)data_packetu+14+IHL,tcp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,tcp->destport,2);
								cpchar((u_char*)data_packetu+14+IHL+12,tcp->flag,2);
								
								zport = hodnota(tcp->sourceport,2);
								cport = hodnota(tcp->destport,2);
								if(zport < 1024){
									nazovsth = nazov(zport,protokoly);
									fprintf(output,"%s\n",nazovsth);
								}
								else if(cport < 1024){
									nazovsth = nazov(cport,protokoly);
									fprintf(output,"%s\n",nazovsth);
								}
								else{
									fprintf(output,"port nie je v subore\n");
								}
								
								
								fprintf(output,"Zdrojovy port: %d\n",zport);
								fprintf(output,"Cielovy port: %d\n",cport);
								
							}
							else if(decimalvalue == 17){
								cpchar((u_char*)data_packetu+14+IHL,udp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,udp->destport,2);
								
								zport = hodnota(udp->sourceport,2);
								cport = hodnota(udp->destport,2);
								if(zport < 1024){
									nazovsth = nazov(zport,protokoly);
									fprintf(output,"%s\n",nazovsth);
								}
								else if(cport < 1024){
									nazovsth = nazov(cport,protokoly);
									fprintf(output,"%s\n",nazovsth);
								}
								else{
									fprintf(output,"port nie je v subore\n");
								}
								
								
								fprintf(output,"Zdrojovy port: %d\n",zport);
								fprintf(output,"Cielovy port: %d\n",cport);
							}
							else if(decimalvalue == 1){
							//	printf("icmp");
							}
							
							
						}
						
						//ipv6
						if(type == 34525){
							cpchar((u_char*)data_packetu+20,sestka->protocol,1);
							cpchar((u_char*)data_packetu+22,sestka->sourceip,16);
							cpchar((u_char*)data_packetu+38,sestka->destip,16);
							vypisIpadriesIPv6(sestka, output);
							decimalvalue = hodnota(sestka->protocol,1);
							nazovsth = nazov(decimalvalue,protokoly);
							fprintf(output,"%s\n",nazovsth);							
						}						
						
						//arp
						if(type == 2054){
							
							cpchar((u_char*)data_packetu+20,arp->operation,2);
							cpchar((u_char*)data_packetu+22,arp->sendermac,6);
							cpchar((u_char*)data_packetu+28,arp->senderip,4);
							cpchar((u_char*)data_packetu+32,arp->targetmac,6);
							cpchar((u_char*)data_packetu+38,arp->targetip,4);
							decimalvalue = hodnota(arp->operation,2);
							
							if(decimalvalue == 1)
								fprintf(output,"request\n");	
							else 
								fprintf(output,"reply\n");
								
							vypisIpadriesARP(arp, output);											
								
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
					int i;
					
					for(i = 0; i < 4; i++){
						if(i == 3)
							fprintf(output,"%d",uzlypomocny->adresa[i]);
						else 	
							fprintf(output,"%d.",uzlypomocny->adresa[i]);
					
					}
					fprintf(output,"\n");
					uzlypomocny = uzlypomocny->next;				
				}
				
				//vypis najpocetnejsieho
				fprintf(output,"Adresa uzla s najv���m po�tom prijatych paketov: \n");
				
				uzlypomocny = uzly;
				uzlymax = uzly;
				maxprijatych = uzlypomocny->prijatych;
				int maximum = 0;
				
				while(uzlypomocny != NULL){
					
					if(uzlypomocny->prijatych > maximum)
						maximum = uzlypomocny->prijatych;
					
					
					uzlypomocny = uzlypomocny->next;				
				}
					
				uzlypomocny = uzly;
				
				
				while(uzlypomocny != NULL){
					
					if(uzlypomocny->prijatych == maximum){
						
						int i;
						for(i = 0; i < 4; i++){
							if(i == 3)
								fprintf(output,"%d",uzlypomocny->adresa[i]);
							else 	
								fprintf(output,"%d.",uzlypomocny->adresa[i]);
						}
						fprintf(output,"\n");
					}
					
					uzlypomocny = uzlypomocny->next;				
				}
				
				
				fprintf(output,"prijatych %d packetov\n",maximum);
				
				//uvolnenie celeho zoznamu
				uzlypomocny = NULL;
				uzlymax = NULL;
				
				while(uzly != NULL){
					uzlypomocny = uzly->next;
					free(uzly);
					uzly = uzlypomocny;
					
				}
				uzlypomocny = NULL;
				uzlymax = NULL;
				uzly = NULL;
			
			}
		
		//***********************************************************************************
		//***********************************************************************************

		//BOD Cislo 4
		else if(modvypisu >= 4 && modvypisu <= 9){
				
				//http
				if(modvypisu == 4){
					port = 80;
					fprintf(output,"HTTP komunikacie\n");
				}
				//https
				else if(modvypisu == 5){
					port = 443;
					fprintf(output,"HTTPs komunikacie\n");
				}
				//telnet
				else if(modvypisu == 6){
					port = 23;
					fprintf(output,"telnet komunikacie\n");
				}
				//ssh
				else if(modvypisu == 7){
					port = 22;
					fprintf(output,"SSH komunikacie\n");
				}
				//ftp riadiace
				else if(modvypisu == 8){
					port = 21;
					fprintf(output,"FTP riadiace komunikacie\n");
				}
				//ftp datove
				else if(modvypisu == 9){
					port = 20;
					fprintf(output,"FTP datove komunikacie\n");
				}
				pocet_komunikacii = 0;
				vypisanych_komunikacii = 0;
				
				porcisloramca = 0;
				while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& /*porcisloramca < 10*/){
					type = 0;
					porcisloramca++;		
					//zistenie typu L2 ramca
					cpchar((u_char*)data_packetu+12,ethernet->type,2);
								
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar(ethernet->type, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
					
						
					if(decimalvalue > 1500){
						type = decimalvalue;
					}
					else{
						continue;						
					}
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
					
						
						//ipv4
						if(type == 2048){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+14,stvorka->ihlv,1);
							cpchar((u_char*)data_packetu+23,stvorka->protocol,1);				
											
							//vypocet IHL a teda kolko je dlzka celej IPv4 hlavicky
							decimalvalue = hodnota(stvorka->ihlv,1);
							IHL = decimalvalue;
							IHL = IHL << 28;
							IHL = IHL >> 28; 
							IHL = IHL * 4;
							//printf("%d\n",IHL);
							
							//analyzovanie vnoreneho protokolu TCP/UDP a adekvatny vypis portu
							decimalvalue = hodnota(stvorka->protocol,1);
		
										
							if(decimalvalue == 6){
								cpchar((u_char*)data_packetu+14+IHL,tcp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,tcp->destport,2);
								cpchar((u_char*)data_packetu+14+IHL+13,tcp->flag,1);
							
								zport = hodnota(tcp->sourceport,2);
								cport = hodnota(tcp->destport,2);
								
								//ak je to hladany typ komunikacie
								if(zport == port || cport == port){
									
									if(zport < cport)
										private_port = cport;
									else
										private_port = zport;
									
									//urcenie aky flag je nastaveny vo flag priznaku	
									flag = 0; 
									flag = hodnota(tcp->flag,1);
									flag = flag << 29;
									flag = flag >> 29;
									
									int i;
									zaznamenane = 0;
									//ci uz je v zaznamoch
									for(i = 0; i < pocet_komunikacii; i++){
										//ak sa nasiel zaznam
										if(pole_komunikacii[i*3] == private_port){
											pole_komunikacii[i*3+1]++;
											//ak bola zacata
											if(pole_komunikacii[i*3+2] != -1){
												//ak je fin
												if(flag == 1)
													pole_komunikacii[i*3+2] += 1;
												//ak je rst
												if(flag == 4)
													pole_komunikacii[i*3+2] += 11;
											}
											zaznamenane = 1;
										}
									}
									//ak neexistoval zaznam este skontrolovat ci je syn
									if(zaznamenane == 0){
										pole_komunikacii[pocet_komunikacii*3] = private_port;
										pole_komunikacii[pocet_komunikacii*3+1] = 1;									
									
										//ak syn tak 0
										if(flag == 2)	
											pole_komunikacii[pocet_komunikacii*3+2] = 0;
										//else -1
										else
											pole_komunikacii[pocet_komunikacii*3+2] = -1;
										pocet_komunikacii++;
									}
									
								}
								
								
							}							
							
						}
						
							
					}
						
					
					
				}//koniec prveho prechodu
			/*
			uplne komunikacie su tie co mali nastavene 
			RST 1x  ==> 11
			FIN + RST ==> 12
			FIN 2x ==> 2
			
			neuplne su 
				nemaju fin 2x ani rst ==> 0
				neboli zacate syn ==> -1
			*/
			/*
			//vysvetlujuci pomocny vypis			
			int i ;
			for(i = 0; i < pocet_komunikacii; i++){
				printf("komunikacia %d\n",i+1);
				printf("port: %d\n",pole_komunikacii[3*i]);
				printf("pocet: %d\n",pole_komunikacii[3*i+1]);
				printf("fin: %d\n",pole_komunikacii[3*i+2]);
			}

			*/
			int i;
			uplna = neuplna = -1;
			for(i = 0; i < pocet_komunikacii; i++){
				//ak sa este nenansla prva neuplna
				if(neuplna == -1){
					//ak je aktualna neuplna
					if(pole_komunikacii[i*3+2] == -1 || pole_komunikacii[i*3+2] == 0 )
						neuplna = i*3;
				}
				//ak sa este nenasla prva neuplna
				if(uplna == -1){
					//ak je aktualna uplna
					if(pole_komunikacii[i*3+2] == 2 || pole_komunikacii[i*3+2] == 11 || pole_komunikacii[i*3+2] == 12)
						uplna = i*3;
				}
			}
			//druhy prechod vypis uplnej a neuplnej komunikacie ak sa vyskytuje 
			porcisloramca = 0;
			pcap_close(pcap_subor);	
			pcap_subor = pcap_open_offline(filepath, chyba_packet_suboru);
			
			if(uplna != -1){
				pocet_komunikacii = pole_komunikacii[uplna+1];
				port = pole_komunikacii[uplna];
				porcisloramca = 0;
				vypisanych_komunikacii = 0;
				fprintf(output,"vypis uplnej komunikacie \n\n");
					while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& /*porcisloramca < 10*/){
					type = 0;
					porcisloramca++;		
					//zistenie typu L2 ramca
					cpchar((u_char*)data_packetu+12,ethernet->type,2);
					cpchar((u_char*)data_packetu,ethernet->Dmac,6);
					cpchar((u_char*)(data_packetu+6),ethernet->Smac,6);
								
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar(ethernet->type, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
					
						
					if(decimalvalue > 1500){
						type = decimalvalue;
					}
					else{
						continue;						
					}
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
					
						
						//ipv4
						if(type == 2048){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+14,stvorka->ihlv,1);
							cpchar((u_char*)data_packetu+23,stvorka->protocol,1);				
							cpchar((u_char*)data_packetu+26,stvorka->sourceip,4);
							cpchar((u_char*)data_packetu+30,stvorka->destip,4);
											
							//vypocet IHL a teda kolko je dlzka celej IPv4 hlavicky
							decimalvalue = hodnota(stvorka->ihlv,1);
							IHL = decimalvalue;
							IHL = IHL << 28;
							IHL = IHL >> 28; 
							IHL = IHL * 4;
							//printf("%d\n",IHL);
							
							//analyzovanie vnoreneho protokolu TCP/UDP a adekvatny vypis portu
							decimalvalue = hodnota(stvorka->protocol,1);
		
										
							if(decimalvalue == 6){
								cpchar((u_char*)data_packetu+14+IHL,tcp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,tcp->destport,2);
								cpchar((u_char*)data_packetu+14+IHL+13,tcp->flag,1);
							
								zport = hodnota(tcp->sourceport,2);
								cport = hodnota(tcp->destport,2);
								
								//ak je to hladany typ komunikacie
								if(zport == port || cport == port){
									
									if(zport < cport)
										private_port = cport;
									else
										private_port = zport;
									
									vypisanych_komunikacii++;
								
									if(vypisanych_komunikacii <= 10 || vypisanych_komunikacii > (pocet_komunikacii-10)){
										fprintf(output,"ramec: %d\n",porcisloramca);
										fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
										fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
										fprintf(output,"Ethernet II\n");
										vypisMacadries(ethernet,output);
										type = hodnota(ethernet->type,2);
										nazovsth = nazov(type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										
										
										if(zport < 1024){
											nazovsth = nazov(zport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else if(cport < 1024){
											nazovsth = nazov(cport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else{
											fprintf(output,"port nie je v subore\n");
										}
										
										
										fprintf(output,"Zdrojovy port: %d\n",zport);
										fprintf(output,"Cielovy port: %d\n",cport);
										
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
								
								
							}							
							
						}
						
							
					}
						
					
					
				}
				
			}
			else fprintf(output,"v subore nie je uplna komunikacie\n");
			porcisloramca = 0;
			pcap_close(pcap_subor);	
			pcap_subor = pcap_open_offline(filepath, chyba_packet_suboru);
			
			if(neuplna != -1){
				pocet_komunikacii = pole_komunikacii[neuplna+1];
				port = pole_komunikacii[neuplna];
				porcisloramca = 0;
				vypisanych_komunikacii = 0;
				fprintf(output,"vypis neuplnej komunikacie\n\n");
					while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& /*porcisloramca < 10*/){
					type = 0;
					porcisloramca++;		
					//zistenie typu L2 ramca
					cpchar((u_char*)data_packetu+12,ethernet->type,2);
					cpchar((u_char*)data_packetu,ethernet->Dmac,6);
					cpchar((u_char*)(data_packetu+6),ethernet->Smac,6);
								
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar(ethernet->type, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
					
						
					if(decimalvalue > 1500){
						type = decimalvalue;
					}
					else{
						continue;						
					}
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
					
						
						//ipv4
						if(type == 2048){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+14,stvorka->ihlv,1);
							cpchar((u_char*)data_packetu+23,stvorka->protocol,1);				
							cpchar((u_char*)data_packetu+26,stvorka->sourceip,4);
							cpchar((u_char*)data_packetu+30,stvorka->destip,4);
											
							//vypocet IHL a teda kolko je dlzka celej IPv4 hlavicky
							decimalvalue = hodnota(stvorka->ihlv,1);
							IHL = decimalvalue;
							IHL = IHL << 28;
							IHL = IHL >> 28; 
							IHL = IHL * 4;
							//printf("%d\n",IHL);
							
							//analyzovanie vnoreneho protokolu TCP/UDP a adekvatny vypis portu
							decimalvalue = hodnota(stvorka->protocol,1);
		
										
							if(decimalvalue == 6){
								cpchar((u_char*)data_packetu+14+IHL,tcp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,tcp->destport,2);
								cpchar((u_char*)data_packetu+14+IHL+13,tcp->flag,1);
							
								zport = hodnota(tcp->sourceport,2);
								cport = hodnota(tcp->destport,2);
								
								//ak je to hladany typ komunikacie
								if(zport == port || cport == port){
									
									if(zport < cport)
										private_port = cport;
									else
										private_port = zport;
									
									vypisanych_komunikacii++;
								
									if(vypisanych_komunikacii <= 10 || vypisanych_komunikacii > (pocet_komunikacii-10)){
										fprintf(output,"ramec: %d\n",porcisloramca);
										fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
										fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
										fprintf(output,"Ethernet II\n");
										vypisMacadries(ethernet,output);
										type = hodnota(ethernet->type,2);
										nazovsth = nazov(type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										
										
										if(zport < 1024){
											nazovsth = nazov(zport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else if(cport < 1024){
											nazovsth = nazov(cport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else{
											fprintf(output,"port nie je v subore\n");
										}
										
										
										fprintf(output,"Zdrojovy port: %d\n",zport);
										fprintf(output,"Cielovy port: %d\n",cport);
										
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
								
								
							}							
							
						}
						
							
					}
						
					
					
				}
				
			}
			else fprintf(output,"v subore nie je neuplna komunikacie\n");
					
		}
		//tfpt
		else if(modvypisu == 10){
				pocet_komunikacii = 0;
				vypisanych_komunikacii = 0;
				port = 69;
				fprintf(output,"vypis tftp komunikacii\n");
				porcisloramca = 0;
				while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& /*porcisloramca < 10*/){
					type = 0;
					porcisloramca++;		
					//zistenie typu L2 ramca
					cpchar((u_char*)data_packetu+12,ethernet->type,2);
								
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar(ethernet->type, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
					
						
					if(decimalvalue > 1500){
						type = decimalvalue;
					}
					else{
						continue;						
					}
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
					
						
						//ipv4
						if(type == 2048){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+14,stvorka->ihlv,1);
							cpchar((u_char*)data_packetu+23,stvorka->protocol,1);				
											
							//vypocet IHL a teda kolko je dlzka celej IPv4 hlavicky
							decimalvalue = hodnota(stvorka->ihlv,1);
							IHL = decimalvalue;
							IHL = IHL << 28;
							IHL = IHL >> 28; 
							IHL = IHL * 4;
							//printf("%d\n",IHL);
							
							//analyzovanie vnoreneho protokolu TCP/UDP a adekvatny vypis portu
							decimalvalue = hodnota(stvorka->protocol,1);
		
							if(decimalvalue == 17){
								cpchar((u_char*)data_packetu+14+IHL,udp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,udp->destport,2);
								
								zport = hodnota(udp->sourceport,2);
								cport = hodnota(udp->destport,2);
							
								if(cport == 69 && port == cport){
									pocet_komunikacii++;
									port = zport;
									//printf("%d %d %d\n",cport, porcisloramca, port);
								}
								else if(cport == port || zport == port){
									pocet_komunikacii++;
								}
									
							
							}							
							
						}
						
							
					}
						
					
					
				}
				//prechod a vypis tftp ramcov
				//printf("tftpcok pre port: %d %d %d\n",pocet_komunikacii,port,porcisloramca);
				porcisloramca = 0;
				pcap_close(pcap_subor);	
				pcap_subor = pcap_open_offline(filepath, chyba_packet_suboru);
				
				while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& /*porcisloramca < 10*/){
					type = 0;
					
					porcisloramca++;
										
					//zistenie typu L2 ramca
					cpchar((u_char*)data_packetu,ethernet->Dmac,6);
					cpchar((u_char*)(data_packetu+6),ethernet->Smac,6);
					cpchar((u_char*)data_packetu+12,ethernet->type,2);
				
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar(ethernet->type, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
						
					if(decimalvalue > 1500){
						type = decimalvalue;
					}
					else{
						continue;						
					}
					
					
					if(type > 0){
					
						
						//ipv4
						if(type == 2048){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+14,stvorka->ihlv,1);
							cpchar((u_char*)data_packetu+23,stvorka->protocol,1);				
							cpchar((u_char*)data_packetu+26,stvorka->sourceip,4);
							cpchar((u_char*)data_packetu+30,stvorka->destip,4);
										
											
							//vypocet IHL a teda kolko je dlzka celej IPv4 hlavicky
							decimalvalue = hodnota(stvorka->ihlv,1);
							IHL = decimalvalue;
							IHL = IHL << 28;
							IHL = IHL >> 28; 
							IHL = IHL * 4;
							//printf("%d\n",IHL);
							
							//analyzovanie vnoreneho protokolu TCP/UDP a adekvatny vypis portu
							decimalvalue = hodnota(stvorka->protocol,1);
		
							if(decimalvalue == 17){
								cpchar((u_char*)data_packetu+14+IHL,udp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,udp->destport,2);
								
								zport = hodnota(udp->sourceport,2);
								cport = hodnota(udp->destport,2);
								if(zport == port || cport == port){
									vypisanych_komunikacii++;
									
									if(vypisanych_komunikacii <= 10 || vypisanych_komunikacii > (pocet_komunikacii-10)){
										fprintf(output,"ramec: %d\n",porcisloramca);
										fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
										fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
										fprintf(output,"Ethernet II\n");
										vypisMacadries(ethernet,output);
										type = hodnota(ethernet->type,2);
										nazovsth = nazov(type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										
										
										if(zport < 1024){
											nazovsth = nazov(zport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else if(cport < 1024){
											nazovsth = nazov(cport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else{
											fprintf(output,"port nie je v subore\n");
										}
										
										
										fprintf(output,"Zdrojovy port: %d\n",zport);
										fprintf(output,"Cielovy port: %d\n",cport);
										
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
							
							}							
							
						}
						
							
					}
				
				}//koniec druheho prechodu
			
		
		
		}
		//bod 4 ICMP
		else if(modvypisu == 11){
				pocet_komunikacii = 0;
				vypisanych_komunikacii = 0;
				fprintf(output,"vypis ICMPx komunikacii\n");
				porcisloramca = 0;
				while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& /*porcisloramca < 10*/){
					type = 0;
					porcisloramca++;		
					//zistenie typu L2 ramca
					cpchar((u_char*)data_packetu+12,ethernet->type,2);
								
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar(ethernet->type, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
					
						
					if(decimalvalue > 1500){
						type = decimalvalue;
					}
					else{
						continue;						
					}
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
					
						
						//ipv4
						if(type == 2048){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+14,stvorka->ihlv,1);
							cpchar((u_char*)data_packetu+23,stvorka->protocol,1);				
											
							//vypocet IHL a teda kolko je dlzka celej IPv4 hlavicky
							decimalvalue = hodnota(stvorka->ihlv,1);
							IHL = decimalvalue;
							IHL = IHL << 28;
							IHL = IHL >> 28; 
							IHL = IHL * 4;
							//printf("%d\n",IHL);
							
							//analyzovanie vnoreneho protokolu TCP/UDP a adekvatny vypis portu
							decimalvalue = hodnota(stvorka->protocol,1);
		
							if(decimalvalue == 1){
								pocet_komunikacii++;	
							}							
							
						}
						
							
					}
						
					
					
				}//koniec prveho prechodu
				porcisloramca = 0;
				pcap_close(pcap_subor);	
				pcap_subor = pcap_open_offline(filepath, chyba_packet_suboru);
				
				while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& /*porcisloramca < 10*/){
					type = 0;
					
					porcisloramca++;
										
					//zistenie typu L2 ramca
					cpchar((u_char*)data_packetu,ethernet->Dmac,6);
					cpchar((u_char*)(data_packetu+6),ethernet->Smac,6);
					cpchar((u_char*)data_packetu+12,ethernet->type,2);
				
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar(ethernet->type, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
						
					if(decimalvalue > 1500){
						type = decimalvalue;
					}
					else{
						continue;						
					}
					
					
					if(type > 0){
					
						
						//ipv4
						if(type == 2048){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+14,stvorka->ihlv,1);
							cpchar((u_char*)data_packetu+23,stvorka->protocol,1);				
							cpchar((u_char*)data_packetu+26,stvorka->sourceip,4);
							cpchar((u_char*)data_packetu+30,stvorka->destip,4);
										
											
							//vypocet IHL a teda kolko je dlzka celej IPv4 hlavicky
							decimalvalue = hodnota(stvorka->ihlv,1);
							IHL = decimalvalue;
							IHL = IHL << 28;
							IHL = IHL >> 28; 
							IHL = IHL * 4;
							//printf("%d\n",IHL);
							
							//analyzovanie vnoreneho protokolu TCP/UDP a adekvatny vypis portu
							decimalvalue = hodnota(stvorka->protocol,1);
		
							if(decimalvalue == 1){
								cpchar((u_char*)data_packetu+14+IHL,icmp->type,1);
								cpchar((u_char*)data_packetu+14+IHL+1,icmp->code,1);
								vypisanych_komunikacii++;
									
									if(vypisanych_komunikacii <= 10 || vypisanych_komunikacii > (pocet_komunikacii-10)){
										fprintf(output,"ramec: %d\n",porcisloramca);
										fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
										fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
										fprintf(output,"Ethernet II\n");
										vypisMacadries(ethernet,output);
										type = hodnota(ethernet->type,2);
										nazovsth = nazov(type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										//vypis type a code
										decimalvalue = hodnota(icmp->type,1);
										int kodik;
										kodik = hodnota(icmp->code,1);
										printf("%d hladane %d %d",porcisloramca,decimalvalue,kodik);
										nazovsth = nazovicmp(decimalvalue,kodik, messages);
										fprintf(output,"%s\n",nazovsth);							
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
							
							}							
							
						}
										
				}//koniec druheho prechodu
		
		}				
		//BOD 4 ARP
		else if(modvypisu == 12){
						
				pocet_komunikacii = 0;
				vypisanych_komunikacii = 0;
				
				porcisloramca = 0;
				while(pcap_next_ex(pcap_subor,&hlavicka_packetu, &data_packetu) == 1 /*&& /*porcisloramca < 10*/){
					type = 0;
					porcisloramca++;		
					//zistenie typu L2 ramca
					cpchar((u_char*)data_packetu+12,ethernet->type,2);
								
					//zistenie obsahu na mieste ethertype 12-14B
					pom = copyuchar(ethernet->type, 2);
					decimalvalue = hodnota(pom, 2);
					free(pom);
					
						
					if(decimalvalue > 1500){
						type = decimalvalue;
					}
					else{
						continue;						
					}
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
					
						
						//arp
						if(type == 2054){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+20,arp->operation,2);
							cpchar((u_char*)data_packetu+22,arp->sendermac,6);
							cpchar((u_char*)data_packetu+28,arp->senderip,4);
							cpchar((u_char*)data_packetu+32,arp->targetmac,6);
							cpchar((u_char*)data_packetu+38,arp->targetip,4);
							decimalvalue = hodnota(arp->operation,2);
								
						}
						
					
					
				}//koniec prveho prechodu
			
			//zistenie poctu komunikacii		
			printf("port: %d pocet: %d\n",port,pocet_komunikacii);
		
		}
					
		}
					
			
		//***********************************************************************************
		//***********************************************************************************
			
		
			fclose(output);
			pcap_close(pcap_subor);	
		}
	
	
	
	//***********************************************************************************
	
	

	return 0;
}


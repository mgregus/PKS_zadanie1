#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <pcap.h>
#include <string.h>


/* run this program using the console pauser or add your own getch, system("pause") or input loop */

//struktura uchovavajuva mac adresy a ethertype
typedef struct Ethernet{
	u_char Dmac[6];
	u_char Smac[6];
	u_char type[2];
}Ethernet;


//struktura uchovavajuca dlzku ipv4 hlavicky, ipv4 adresy, a protokol vyssej(L4) vrstvy
typedef struct IPv4{
	u_char ihlv[1];
	u_char protocol[1];
	u_char sourceip[4];
	u_char destip[4];
}IPv4;

//struktura uchovavajuva ipv4 adresy, a protokol vyssej(L4) vrstvy
typedef struct IPv6{
	u_char protocol[1];
	u_char sourceip[16];
	u_char destip[16];
}IPv6;


//struktura uchovavajuca potrebne udaje pre arp protokol
typedef struct ARP{
	//request /reply
	u_char operation[2];
	
	//request unicast mac of sender
	//reply unicast mac of reciever which was unknown before request was sent
	u_char sendermac[6];
	u_char senderip[4];
	
	//request broadcast ff:ff
	//reply unicast address
	u_char targetmac[6];
	u_char targetip[4];
}ARP;

//struktura uchovavajuca zdrojovy a cielovy port a potrebne flagy nastavene v tcp hlavicke
typedef struct TCP{
	u_char sourceport[2];
	u_char destport[2];
	u_char flag[1];
}TCP;

//struktura uchovavajuca typ a kod z hlavicky icmp protokolu
typedef struct ICMP{
	u_char type[1];
	u_char code[1];
}ICMP;

//struktura uchovavajuca zdrojovy a cielovy port z tcp hlavicky
typedef struct UDP{
	u_char sourceport[2];
	u_char destport[2];
}UDP;


//struktura sluziaca na vytvorenie spajaneho zoznamu pre Ip adresy prijimajucich uzlov
typedef struct UZLY{
	u_char *adresa;
	int prijatych;
	struct UZLY *next;
}UZLY;


//funkcia vypocita dlzku ramcu ktori realne presiel po mediu
//vstupom funckie je velkost ramcu api
int dlzka_paketu_po_mediu(int apilength){
	int medialength = 0;
		
	if(apilength >= 60)
		medialength = apilength + 4;
	
	else
		medialength = 64;
	
	return medialength;
}

//funckia vrati na podretazec o dlzke n znakov z retazca na vstupe
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


//funkcia skopiruje n znakov zo zdrojoveho retazca do cieloveho retazca
void cpchar(u_char *source,u_char *dest, int n){
	int i;
	
	for(i = 0; i < n; i++){
		dest[i] = source[i];
	}	
	
}


//postupnost bajtov zmeni na desiatkove cislo, funguje len do 4B(kapacita int premmenej)
//funkcia vrati desiatkovu hondotu cisla, ktore je reprezentovane ako postupnost bajtov
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

//funkcia vypise mac adresy z ethernet struktury do suboru
//vstupom je ethernet struktura, a subor
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

//funkcia vypise ipv4 adresy z ipv4 struktury do suboru
//vstupom je ipv4 struktura, a subor
void vypisIpadriesIP(IPv4 *pt, FILE *output){
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


//funkcia vypise ipv6 adresy z ipv4 struktury do suboru
//vstupom je ipv6 struktura, a subor
void vypisIpadriesIPv6(IPv6 *pt, FILE *output){
			int i;			
			fprintf(output,"Zdrojová Ipv6 adresa: ");
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
			
			fprintf(output,"Cielová Ipv6 adresa: ");
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


//funkcia vypisi ip adresy z arp struktury do suboru
//vstupom je arp struktura a subor
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

//vypisanie ip adries zo spajaneho zoznamu do suboru
//vstup je jeden zaznam zo spajaneho zoznamu, a subor
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


//funkcia vrati nazov portu alebo protokolu(pre jeho cislo) zo suboru
//vstupom je vrstva na ktorej sa nachadza protokol ku ktoreho cislu chceme urcit nazov
//cislo tohto protokolu/portu
//nazov suboru, z ktoreho citame
char *nazov(int layer, int code, FILE *subor){
	rewind(subor);
	char *name;
	name = malloc(200*sizeof(char));
	char *pom;
	pom = malloc(200*sizeof(char));
	char c;
	char found = 0;
	int vrstva;
	char novy;
	int pomcode;    
/*	if(layer == 3)
	printf("%d %d\n",layer, code);*/
	novy = 0; 
	//citanie do konca suboru
	while((c=getc(subor)) != EOF){
        if(c >= 48  && c <= 57){
        	ungetc(c,subor); 
		 
			fscanf(subor,"%d",&vrstva);
			fscanf(subor,"%x",&pomcode);
			fscanf(subor,"%[^\n]s",pom);		
			
			//ak sme nasli hladany kod
			if(vrstva == layer){
    				if(pomcode == code){
						found = 1;
					//	fscanf(subor,"%[^\n]s",name);
						return pom;
				}
			}
			
		}
	
	}
    //odstranenie medzeri
	if(found == 1)
		return name;
	return "dany zaznam nie je v externom subore\0";
}


//vrati cislo portu zo suboru
//vstupom je nazov portu/protokolu
//subor, z  ktoreho ma citat
int cisloportu(char *ret, FILE *subor){
	int cislo;
	rewind(subor);
	char *name;
	name = malloc(200*sizeof(char));

	while(fscanf(subor,"%s",name) != EOF){
		if(strcmp(ret, name) == 0){
			fscanf(subor,"%d",&cislo);
			return cislo;
		}
	}
	
	return -1;
}


//funkcia vrati ICMP spravu(pre jej typ a code cislo) zo suboru
//vstupom je typ icmp spravy ku ktoreho cislu chceme urcit obsah spravy
//code hondota pre dany typ 
//nazov suboru, z ktoreho citame
char *nazovicmp(int type, int code, FILE *subor){
	rewind(subor);
	char *name;
	name = malloc(200*sizeof(char));
	char *pom;
	pom = malloc(200*sizeof(char));
	char c;
	char found = 0;
	int hodnotasth;
	char novy;
	int pomcode;    
	
	
	//citanie do konca suboru
	novy = 0; 
	while((c=getc(subor)) != EOF){
		//printf("%c",c);
		//ak sme nasli zhodu
        if(c >= 48  && c <= 57){
        	ungetc(c,subor);  
			fscanf(subor,"%d",&hodnotasth);
			fscanf(subor,"%d",&pomcode);
			if(hodnotasth == type){
    				if(pomcode == code){
						found = 1;
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
	
	//definuje aky obsah .pcap suboru bude vypisany
	int modvypisu = 0;
	
	int pocetvypisov = 0;
	//***********************************************************************************
	
	//pomocne .txt subory
	FILE *output;//vypis programu
	FILE *protokoly;//mena protokolov a portov
	FILE *cisla;//cisla portov a aj niektorych protokolov
	FILE *messages;//icmp spravy
	protokoly = fopen("protokoly1.txt","r");
	if(protokoly == NULL){
		printf("neda sa otvorit externy subor protokoly\n");
		return 2;
	}
	cisla = fopen("cisla.txt","r");
	if(cisla == NULL){
		printf("neda sa otvorit externy subor cisla\n");
		return 2;
	}
	messages = fopen("messages.txt","r");
	if(messages == NULL){
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
	u_char *pom; // pomocnna premmenna obvykle len na ulozenie postupnosti bajtov, z ktorich zistime decimalnu hodnotu
	int decimalvalue;//decimalna hodnota nejakej postupnosti bajtov
	char *nazovsth;//nazov protokolu/portu nacitany zo suboru
	int type;//ethertype zistene z ramca
	int zport,cport;//cislo zdrojoveho, cieloveho portu zistene z ramca		
	int IHL; //dlzka ip hlavicky zistena z ramca
	int maxprijatych;//pre uzol ip, ktori prijal najviac ramcov
	int porcisloramca = 0;
	int port;//pomocne cislo portu
	int pocet_komunikacii;//pocet nejakej konkretnej komunikacie vo filtre
	int vypisanych_komunikacii;//pocet uz vypisanych komunikacii potrebne pre dodrzanie vypisu prvych 10  a poslednych 10 ramcov
	int pole_komunikacii[6500] = {0}; // pomocne pole na ukladanie hodnot potrebne pre filtre
	int private_port; 
	u_int flag; // hodnota flagu tcp nacitana z ramcu
	int uplna, neuplna; //sem sa uklada ktori zaznam z pole_komunikacii je uplna a ktora neuplna komunikacia
	int operation; // arp typ operacie nacitany zo suboru
	char zaznamenane; // pomocna premmena 
	char aktualizovane; //pomocna premmenaa
	char rovnake; // pomocna premmnnna
	//***********************************************************************************
	
	
	//l2 struktury
	Ethernet *ethernet = malloc(sizeof(Ethernet));
	//***********************************************************************************
	
	//l3struktury
	IPv6 *sestka = malloc(sizeof(IPv6));
	ARP *arp = malloc(sizeof(ARP));
	IPv4 *stvorka = malloc(sizeof(IPv4));
	//pre potreby spajaneho zoznamu pre zistenie ip uzlov, ktore prijali najviac ramcov
	UZLY *uzly = NULL;
	UZLY *uzlypomocny = NULL;
	UZLY *uzlymax = NULL;
	
	//***********************************************************************************
	
	//L4 struktury
	UDP *udp = malloc(sizeof(UDP));
	TCP *tcp = malloc(sizeof(TCP));
	ICMP *icmp = malloc(sizeof(ICMP));
	
	/*
	//testovacivypis
	printf("http %d\n",cisloportu("http\0",cisla));
	printf("tftp %d\n",cisloportu("tftp\0",cisla));
	printf("ssh %d\n",cisloportu("ssh\0",cisla));
	printf("icmp %d\n",cisloportu("icmp\0",cisla));
	printf("telnet %d\n",cisloportu("telnet\0",cisla));
	printf("ftp-d %d\n",cisloportu("ftp-d\0",cisla));
	printf("ftp-r %d\n",cisloportu("ftp-r\0",cisla));
	printf("ipv4 %d\n",cisloportu("ipv4\0",cisla));
	printf("arp %d\n",cisloportu("arp\0",cisla));
	*/
	
	//nacitanie niektorych nazvov portov zo suboru najme pre potrebu vypisu na 4 vrstve
	int styriarp = cisloportu("arp\0",cisla);
	int styritcp = cisloportu("tcp\0",cisla);
	int styriudp = cisloportu("udp\0",cisla);
	int sipv4 = cisloportu("ipv4\0",cisla);
	int sipv6 = cisloportu("ipv6\0",cisla);
	int sigmp = cisloportu("igmp\0",cisla);
	int sicmp = cisloportu("icmp\0",cisla);
	
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
	printf("vypis bodu 4i) ARP zadajte 12\n");
	printf("vypis bodu 4i) TFTP po jednotlivych komunikaciach zadajte 13\n");
	printf("vypis doimplementacia 14\n\n");
	//***********************************************************************************
	
	
	//cyklus v ktorom si nacitam vzdy novy subor a vypisem pren konkretny typ vypisu 
	while(modvypisu != -1){
	
		//otvorenie konkretneho .pcap suboru z priecinku podla uzivatelovej volby
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
			//ukoncenie programu ak si zvolime modvypisu pre koniec
			if(modvypisu == -1){	
			break;
			}
			continue;
		}
		
		//pridava vzdy i+1 do nazvu vypisu pre vypis v kazdom cykle
		pocetvypisov++;
		sprintf(nazovvypisu,"output%d.txt",pocetvypisov);
		output = fopen(nazovvypisu,"w");
		
		//vyber modu vypisu
		printf("zadajte mod vypisu: \n");
		scanf("%d",&modvypisu);
		
		//ukoncenie programu
		if(modvypisu == -1){
			fclose(output);
			pcap_close(pcap_subor);			
			break;
		}
		
			//***********************************************************************************
		//vypis vsetkeho potrebneho definovaneho v bodoch 1 az 3
		else if(modvypisu >= 1 && modvypisu <= 3){
			
				porcisloramca = 0;
				//nacitavanie ramcov do konca .pcap suboru
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
					
					//ak je vacsi ako 1500 tak je to ethernet
					if(decimalvalue > 1500){
						fprintf(output,"Ethernet II\n");
						type = decimalvalue;
					}//inak ieee
					else{
						
						fprintf(output,"IEEE 802.3 ");
						pom = copyuchar((u_char*)data_packetu+15,1);	
						decimalvalue = hodnota(pom, 1);	
						free(pom);
						
						//raw/lcc/llc+snap if splnene tak je to raw
						if(decimalvalue == 255){
							
							fprintf(output,"- Raw\n");
							vypisMacadries(ethernet,output);
							nazovsth = nazov(2,decimalvalue,protokoly);
							fprintf(output,"%s\n",nazovsth);
						
						}//llc/llc+snap
						else{
							
							pom = copyuchar((u_char*)data_packetu+15,1);
							decimalvalue = hodnota(pom, 1);	
							free(pom);
							
							
							//ma llc aj snap
							if(decimalvalue == 170){
								fprintf(output," s LLC a SNAP\n");
								nazovsth = nazov(2,decimalvalue,protokoly);
								fprintf(output,"SSAP: %s\n",nazovsth);
								pom = copyuchar((u_char*)data_packetu+20,2);
								decimalvalue = hodnota(pom, 2);
								free(pom);
								vypisMacadries(ethernet,output);	
								nazovsth = nazov(2,decimalvalue,protokoly);
								
								fprintf(output,"Ether type: %s\n",nazovsth);
							}//ma llc
							else{
								fprintf(output," s LLC\n");
								vypisMacadries(ethernet,output);	
								pom = copyuchar((u_char*)data_packetu+15,1);
								decimalvalue = hodnota(pom, 1);	
								free(pom);
								nazovsth = nazov(2,decimalvalue,protokoly);
								fprintf(output,"%s\n",nazovsth);
							}					
						}
					
					
					}
					
					
					
					
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
						vypisMacadries(ethernet,output);
						nazovsth = nazov(2,type,protokoly);
						fprintf(output,"%s\n",nazovsth);
						
						//ipv4
						if(type == 2048){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+14,stvorka->ihlv,1);
							cpchar((u_char*)data_packetu+23,stvorka->protocol,1);
							cpchar((u_char*)data_packetu+26,stvorka->sourceip,4);
							cpchar((u_char*)data_packetu+30,stvorka->destip,4);
							vypisIpadriesIP(stvorka, output);
							decimalvalue = hodnota(stvorka->protocol,1);
							nazovsth = nazov(3,decimalvalue,protokoly);
							fprintf(output,"%s\n",nazovsth);
							
							//monitorovanie ipv4 adries prijimajucich uzlov za ucelom zistenie ktori uzol prijal najviac
							//jednotlive adresy su ulozene v spajanom zozname, nizsie je sprava spajaneho zoznamu spravena
							
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
		
							//ak je tcp			
							if(decimalvalue == 6){
								cpchar((u_char*)data_packetu+14+IHL,tcp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,tcp->destport,2);
								cpchar((u_char*)data_packetu+14+IHL+12,tcp->flag,2);
								
								zport = hodnota(tcp->sourceport,2);
								cport = hodnota(tcp->destport,2);
								//zistenie vnorenych portov
								if(zport < 1024){
									nazovsth = nazov(4,zport,protokoly);
									fprintf(output,"%s\n",nazovsth);
								}
								else if(cport < 1024){
									nazovsth = nazov(4,cport,protokoly);
									fprintf(output,"%s\n",nazovsth);
								}
								else{
									nazovsth = nazov(4,zport,protokoly);
									
									if(strstr(nazovsth,"dany zaznam") != NULL)
										fprintf(output,"%s\n",nazovsth);
										
									nazovsth = nazov(4,cport,protokoly);
									
									if(strstr(nazovsth,"dany zaznam") != NULL)
										fprintf(output,"%s\n",nazovsth);
									else 
										fprintf(output,"port nie je v subore\n");
								}
								
								
								fprintf(output,"Zdrojovy port: %d\n",zport);
								fprintf(output,"Cielovy port: %d\n",cport);
								
							}//ak je udp
							else if(decimalvalue == 17){
								cpchar((u_char*)data_packetu+14+IHL,udp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,udp->destport,2);
								
								zport = hodnota(udp->sourceport,2);
								cport = hodnota(udp->destport,2);
								if(zport < 1024){
									nazovsth = nazov(4,zport,protokoly);
									fprintf(output,"%s\n",nazovsth);
								}
								else if(cport < 1024){
									nazovsth = nazov(4,cport,protokoly);
									fprintf(output,"%s\n",nazovsth);
								}
								else{
									nazovsth = nazov(4,zport,protokoly);
									
									if(strstr(nazovsth,"dany zaznam") != NULL)
										fprintf(output,"%s\n",nazovsth);
										
									nazovsth = nazov(4,cport,protokoly);
									
									if(strstr(nazovsth,"dany zaznam") != NULL)
										fprintf(output,"%s\n",nazovsth);
									else 
										fprintf(output,"port nie je v subore\n");
								}
								
								
								fprintf(output,"Zdrojovy port: %d\n",zport);
								fprintf(output,"Cielovy port: %d\n",cport);
							}//ak je icmp
							else if(decimalvalue == 1){
								cpchar((u_char*)data_packetu+14+IHL,icmp->type,1);
								cpchar((u_char*)data_packetu+14+IHL+1,icmp->code,1);
								
								decimalvalue = hodnota(icmp->type,1);
								int kodik;
								kodik = hodnota(icmp->code,1);
								nazovsth = nazovicmp(decimalvalue,kodik, messages);
								fprintf(output,"%s\n",nazovsth);	
							}
							
							
						}
						
						//ipv6
						if(type == 34525){
							cpchar((u_char*)data_packetu+20,sestka->protocol,1);
							cpchar((u_char*)data_packetu+22,sestka->sourceip,16);
							cpchar((u_char*)data_packetu+38,sestka->destip,16);
							vypisIpadriesIPv6(sestka, output);
							decimalvalue = hodnota(sestka->protocol,1);
							nazovsth = nazov(3,decimalvalue,protokoly);
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
			
				uzlypomocny = uzly;
				//vypis vsetkych ip adries prijimajucich uzlov
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
				fprintf(output,"Adresa uzla s najväèším poètom prijatych paketov: \n");
				//prebehnutie celeho zoznamu pre zistenie ake je maximum prijatych sprav
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
				
				//vypisanie ip uzla, ktori prijal najviac paketov
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
				//v podmienkach je nacitane cislo portu zo suboru, ktoreho vyskyt v .pcap subore filtrujeme
				//http
				if(modvypisu == 4){
					port = cisloportu("http\0",cisla);
					fprintf(output,"HTTP komunikacie\n");
				}
				//https
				else if(modvypisu == 5){
					port = cisloportu("https\0",cisla);
					fprintf(output,"HTTPs komunikacie\n");
				}
				//telnet
				else if(modvypisu == 6){
					port = cisloportu("telnet\0",cisla);
					fprintf(output,"telnet komunikacie\n");
				}
				//ssh
				else if(modvypisu == 7){
					port = cisloportu("ssh\0",cisla);
					fprintf(output,"SSH komunikacie\n");
				}
				//ftp riadiace
				else if(modvypisu == 8){
					port = cisloportu("ftp-r\0",cisla);
					fprintf(output,"FTP riadiace komunikacie\n");
				}
				//ftp datove
				else if(modvypisu == 9){
					port = cisloportu("ftp-d\0",cisla);
					fprintf(output,"FTP datove komunikacie\n");
				}
				
				int i ;
				for(i = 0; i < 6500; i++){
					pole_komunikacii[i] = 0;
				}	
				pocet_komunikacii = 0;
				vypisanych_komunikacii = 0;
				
				//ziskanie informacii o ramcoch potrebne pre spravny vypis
				//vysvetlenie hondot v pole_komunikacii
				//hodnota na mieste i udava cislo privatneho portu
				//hondota na mieste i+1 udava pocet ramcov z danej komunikacie
				//hodnota na mieste i+3 udava ci je komunikacia ukoncena alebo neukoncena vysvetlenie pre jednotlive stavy ukocena/neukoncena
				/*	
				RST 1x  ==> 11
				FIN + RST ==> 12
				FIN 2x ==> 2
			
				neuplne su 
				nemaju fin 2x ani rst ==> 0
				neboli zacate syn ==> -1*/
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
		
										
							if(decimalvalue == styritcp){
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
			
			//zistenie z pola ktora komunikacia je prva neuplna a prva uplna
			uplna = neuplna = -1;
			for(i = 0; i < pocet_komunikacii; i++){
				//ak sa este nenansla prva neuplna
				if(neuplna == -1){
					//ak je aktualna neuplna
					if(pole_komunikacii[i*3+2] == 0 || pole_komunikacii[i*3+2] == 1)
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
			//vypis uplnej komunikacie
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
		
										
							if(decimalvalue == styritcp){
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
									//konkretny vypis potrebnych ramcov z komunikacie
									if(vypisanych_komunikacii <= 10 || vypisanych_komunikacii > (pocet_komunikacii-10)){
										fprintf(output,"ramec: %d\n",porcisloramca);
										fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
										fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
										fprintf(output,"Ethernet II\n");
										vypisMacadries(ethernet,output);
										type = hodnota(ethernet->type,2);
										nazovsth = nazov(2,type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(3,decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										
										
										if(zport < 1024){
											nazovsth = nazov(4,zport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										
										else if(cport < 1024){
											nazovsth = nazov(4,cport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else{
											nazovsth = nazov(4,zport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											
											nazovsth = nazov(4,cport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											else 
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
			fprintf(output,"------------------------------------------------------------------------------\n");
			//vypis neuplnej komunikacie
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
		
										
							if(decimalvalue == styritcp){
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
								//konkretny vypis potrebnych ramcov z komunikacie
									if(vypisanych_komunikacii <= 10 || vypisanych_komunikacii > (pocet_komunikacii-10)){
										fprintf(output,"ramec: %d\n",porcisloramca);
										fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
										fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
										fprintf(output,"Ethernet II\n");
										vypisMacadries(ethernet,output);
										type = hodnota(ethernet->type,2);
										nazovsth = nazov(2,type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(3,decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										
										
										if(zport < 1024){
											nazovsth = nazov(4,zport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else if(cport < 1024){
											nazovsth = nazov(4,cport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else{
											nazovsth = nazov(4,zport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											
											nazovsth = nazov(4,cport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											else 
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
		//tfpt vypis ramcov jednej tftp komunikacie
		else if(modvypisu == 10){
				pocet_komunikacii = 0;
				vypisanych_komunikacii = 0;
				port = cisloportu("tftp\0",cisla);;
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
										nazovsth = nazov(2,type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(3,decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										
										
										if(zport < 1024){
											nazovsth = nazov(4,zport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else if(cport < 1024){
											nazovsth = nazov(4,cport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else{
											nazovsth = nazov(4,zport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											
											nazovsth = nazov(4,cport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											else 
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
										nazovsth = nazov(2,type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(3,decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										//vypis type a code
										decimalvalue = hodnota(icmp->type,1);
										int kodik;
										kodik = hodnota(icmp->code,1);
										//printf("%d hladane %d %d",porcisloramca,decimalvalue,kodik);
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
				int i ;
				for(i = 0; i < 6500; i++){
					pole_komunikacii[i] = 0;
				}	
					
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
						if(type == styriarp){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+20,arp->operation,2);
							cpchar((u_char*)data_packetu+22,arp->sendermac,6);
							cpchar((u_char*)data_packetu+28,arp->senderip,4);
							cpchar((u_char*)data_packetu+32,arp->targetmac,6);
							cpchar((u_char*)data_packetu+38,arp->targetip,4);
							//ci je request / reply
							operation = hodnota(arp->operation,2);
							//berieme ip adresu v zavislosti od typu operacie
							if(operation == 1){
								decimalvalue = hodnota(arp->targetip,4);
							}
							else if(operation == 2){
								decimalvalue = hodnota(arp->senderip,4);
							}
							
							zaznamenane = 0;
							//printf("ramec: %d decimalvalue %d\n",porcisloramca,decimalvalue);
							//zistime ci ide o staru komunikaciu
							for(i = 0; i < pocet_komunikacii; i++){
								if(operation == 1){
									//je to request a teda patri k requestu na ktori este nebol reply cize ta ista komunikacia
									if(pole_komunikacii[i*2] == decimalvalue && pole_komunikacii[i*2+1] == -1){
										zaznamenane = 1;
										break;
									}
								}
								else if(operation == 2){
									//ak bola komunikacia requesty bez reply na danu adresu, tak toto ukoncuje komunikaciu
									if(pole_komunikacii[i*2] == decimalvalue && pole_komunikacii[i*2+1] == -1){
										zaznamenane = 1;
										pole_komunikacii[i*2+1] = porcisloramca;
										break;
									}
								}
							} 
							
							//ide o novu komunikaciu
							if(zaznamenane == 0){
								pole_komunikacii[pocet_komunikacii*2] = decimalvalue;
								if(operation == 1)
									pole_komunikacii[pocet_komunikacii*2+1] = -1;
								else if(operation == 2)
									pole_komunikacii[pocet_komunikacii*2+1] = porcisloramca;
								pocet_komunikacii++;
							}
								
						}
						
					
					
				}
			
		
			}//koniec prveho prechodu
			
			porcisloramca = 0;
			pcap_close(pcap_subor);	
			pcap_subor = pcap_open_offline(filepath, chyba_packet_suboru);
			//printf("k3 %d\n",pocet_komunikacii);
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
					
					//vypis vnoreneho protokolu pre ethernet
					if(type > 0){
					
						
						//arp
						if(type == styriarp){
							
							//aj tu prerobene
							cpchar((u_char*)data_packetu+20,arp->operation,2);
							cpchar((u_char*)data_packetu+22,arp->sendermac,6);
							cpchar((u_char*)data_packetu+28,arp->senderip,4);
							cpchar((u_char*)data_packetu+32,arp->targetmac,6);
							cpchar((u_char*)data_packetu+38,arp->targetip,4);
							//ci je request / reply
							operation = hodnota(arp->operation,2);
							//berieme ip adresu v zavislosti od typu operacie
							if(operation == 1){
								decimalvalue = hodnota(arp->targetip,4);
							}
							else if(operation == 2){
								decimalvalue = hodnota(arp->senderip,4);
							}
							
							//zistime cislo komunikacie
								
							for(i = 0; i < pocet_komunikacii; i++){
								if(operation == 1){
									
									if(pole_komunikacii[i*2] == decimalvalue && ((pole_komunikacii[i*2+1] == -1) || ( porcisloramca <= pole_komunikacii[i*2+1]))){
										vypisanych_komunikacii = i+1;
										break;
									}
								}
								else if(operation == 2) {
								
									if(pole_komunikacii[i*2+1] == porcisloramca){
										vypisanych_komunikacii = i+1;
										break;
									}
								}
							} 
														
							fprintf(output,"komunikacia cislo: %d\n",vypisanych_komunikacii);
							if(operation == 1){
								fprintf(output,"ARP request, ");
								fprintf(output,"IP adresa: %d.%d.%d.%d, MAC adresa: ?????\n",arp->senderip[0],arp->senderip[1],arp->senderip[2],arp->senderip[3]);
								vypisIpadriesARP(arp, output);
								fprintf(output,"ramec: %d\n",porcisloramca);	
								fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
								fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
								fprintf(output,"Ethernet II\n");
								type = hodnota(ethernet->type,2);
								nazovsth = nazov(2,type,protokoly);
								fprintf(output,"%s\n",nazovsth);
								vypisMacadries(ethernet,output);
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
							if(operation == 2){
								fprintf(output,"ARP reply, ");
								fprintf(output,"IP adresa: %d.%d.%d.%d, MAC adresa: %.2x %.2x %.2x %.2x %.2x %.2x\n",arp->senderip[0],arp->senderip[1],arp->senderip[2],arp->senderip[3],arp->sendermac[0],arp->sendermac[1],arp->sendermac[2],arp->sendermac[3],arp->sendermac[4],arp->sendermac[5]);
								vypisIpadriesARP(arp, output);
								fprintf(output,"ramec: %d\n",porcisloramca);	
								fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
								fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
								fprintf(output,"Ethernet II\n");
								type = hodnota(ethernet->type,2);
								nazovsth = nazov(2,type,protokoly);
								fprintf(output,"%s\n",nazovsth);
								vypisMacadries(ethernet,output);
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
			
		
			//printf("port: %d pocet: %d\n",port,pocet_komunikacii);
		
			}	
		
		}//arp
					
			
		//***********************************************************************************
		//TFTP v2 vypis vsetkych komunikacii tfpt
		else if(modvypisu == 13){
				
				int i ;
				for(i = 0; i < 6500; i++){
					pole_komunikacii[i] = 0;
				}	
				port = cisloportu("tftp\0",cisla);		
				pocet_komunikacii = 0;
				vypisanych_komunikacii = 0;
				fprintf(output,"vypis tftp komunikacii\n");
				porcisloramca = 0;
				//zistenie pomocnych informacii
				//pole_komunikacii[i] je cislo portu1
				//pole_komunikacii[i+1] je cislo portu2
				//pole_komunikacii[i+2] pocet ramcov danej komunikacie
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
								//**************
									int i;
									zaznamenane = 0;
									//ak neexistoval zaznam a ide o prvu komunikaciu na port 69 sem sa da dat port
									if(cport == 69){
										pole_komunikacii[i*2] = zport;
										pole_komunikacii[i*2+1] = 1;
										pocet_komunikacii++;
										zaznamenane == 1;
									}
									//prehladanie zaznamov, ci sa to tyka niektorej z doposial tftp komunikacii
									else{
										for(i = 0; i < pocet_komunikacii; i++){
											//ak sa nasiel zaznam tak pridame pocet komunikacii
											if(pole_komunikacii[i*2] == cport || pole_komunikacii[i*2] == zport){
												pole_komunikacii[i*2+1]++;
											}
										}
									}
									//******************						
							
							}							
							
						}
						
							
					}
						
					
					
				}
				//prechod a vypis tftp ramcov
				//printf("tftpcok pre port: %d %d %d\n",pocet_komunikacii,port,porcisloramca);
				
				
				//vypis vsetkych komunikacii tfpt podla bodu 4
				
				for(i = 0; i < pocet_komunikacii; i++){
						porcisloramca = 0;
						pcap_close(pcap_subor);	
						pcap_subor = pcap_open_offline(filepath, chyba_packet_suboru);
						vypisanych_komunikacii = 0;
						fprintf(output,"----------------------------------------------------------------------------\n");
						fprintf(output,"komunikacia cislo %d\n",i+1);
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
										if(zport == pole_komunikacii[i*2] || cport == pole_komunikacii[i*2]){
											vypisanych_komunikacii++;
											//vypis konkretnej komunikacie
											if(vypisanych_komunikacii <= 10 || vypisanych_komunikacii > (pole_komunikacii[i*2+1]-10)){
												fprintf(output,"ramec: %d\n",porcisloramca);
												fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
												fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
												fprintf(output,"Ethernet II\n");
												vypisMacadries(ethernet,output);
												type = hodnota(ethernet->type,2);
												nazovsth = nazov(2,type,protokoly);
												fprintf(output,"%s\n",nazovsth);
												vypisIpadriesIP(stvorka, output);
												decimalvalue = hodnota(stvorka->protocol,1);
												nazovsth = nazov(3,decimalvalue,protokoly);
												fprintf(output,"%s\n",nazovsth);
							
												
												
												if(zport < 1024){
													nazovsth = nazov(4,zport,protokoly);
													fprintf(output,"%s\n",nazovsth);
												}
												else if(cport < 1024){
													nazovsth = nazov(4,cport,protokoly);
													fprintf(output,"%s\n",nazovsth);
												}
												else{
													nazovsth = nazov(4,zport,protokoly);
													if(strstr(nazovsth,"dany zaznam") != NULL)
														fprintf(output,"%s\n",nazovsth);
													
													nazovsth = nazov(4,cport,protokoly);
													if(strstr(nazovsth,"dany zaznam") != NULL)
														fprintf(output,"%s\n",nazovsth);
													else 
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
				}//koniec druheho prechodu
			
		
		}
		
		//doimplementacia
		else if(modvypisu == 14){
				pocet_komunikacii = 0;
				port = cisloportu("http\0",cisla);
				porcisloramca = 0;
				fprintf(output,"vypis doimplementacie \n\n");
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
					
						//keby nieco na L3 tak sem inak staci len nastavit cislo portu pre L2
						
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
		
										
							if(decimalvalue == styritcp){
								cpchar((u_char*)data_packetu+14+IHL,tcp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,tcp->destport,2);
								cpchar((u_char*)data_packetu+14+IHL+13,tcp->flag,1);
							
								zport = hodnota(tcp->sourceport,2);
								cport = hodnota(tcp->destport,2);
								
								if(zport == port || cport == port){
									pocet_komunikacii++;	
								
									//konkretny vypis potrebnych ramcov z komunikacie
										fprintf(output,"ramec: %d\n",porcisloramca);
										fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
										fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
										fprintf(output,"Ethernet II\n");
										vypisMacadries(ethernet,output);
										type = hodnota(ethernet->type,2);
										nazovsth = nazov(2,type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(3,decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										
										
										if(zport < 1024){
											nazovsth = nazov(4,zport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										
										else if(cport < 1024){
											nazovsth = nazov(4,cport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else{
											nazovsth = nazov(4,zport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											
											nazovsth = nazov(4,cport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											else 
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
							else if(decimalvalue == styriudp){
								cpchar((u_char*)data_packetu+14+IHL,udp->sourceport,2);
								cpchar((u_char*)data_packetu+14+IHL+2,udp->destport,2);
						
								zport = hodnota(udp->sourceport,2);
								cport = hodnota(udp->destport,2);
								
								if(zport == port || cport == port){
									pocet_komunikacii++;	
								
									//konkretny vypis potrebnych ramcov z komunikacie
										fprintf(output,"ramec: %d\n",porcisloramca);
										fprintf(output,"dlzka poskytnuta pcap API - %d B\n",hlavicka_packetu->caplen);
										fprintf(output,"dlzka prenasana po mediu - %d B\n",dlzka_paketu_po_mediu(hlavicka_packetu->caplen));
										fprintf(output,"Ethernet II\n");
										vypisMacadries(ethernet,output);
										type = hodnota(ethernet->type,2);
										nazovsth = nazov(2,type,protokoly);
										fprintf(output,"%s\n",nazovsth);
										vypisIpadriesIP(stvorka, output);
										decimalvalue = hodnota(stvorka->protocol,1);
										nazovsth = nazov(3,decimalvalue,protokoly);
										fprintf(output,"%s\n",nazovsth);
					
										
										
										if(zport < 1024){
											nazovsth = nazov(4,zport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										
										else if(cport < 1024){
											nazovsth = nazov(4,cport,protokoly);
											fprintf(output,"%s\n",nazovsth);
										}
										else{
											nazovsth = nazov(4,zport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											
											nazovsth = nazov(4,cport,protokoly);
											if(strstr(nazovsth,"dany zaznam") != NULL)
												fprintf(output,"%s\n",nazovsth);
											else 
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
				fprintf(output,"pocet sledovanych ramcov %d\n",pocet_komunikacii);
				
		}			
	
		//***********************************************************************************
			
		
			fclose(output);
			pcap_close(pcap_subor);	
		}
	
	
	
	//***********************************************************************************
	
	

	return 0;
}


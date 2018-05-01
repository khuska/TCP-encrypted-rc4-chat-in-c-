#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <err.h>
#include <pthread.h>
#define N 256   // 2^8
#define PRIVATE_KEY 45161;
static char key[255];

int modulo(int suuri,int zereg,int m){
    unsigned long  base = 1, binary = 0;
    int remainder;
    while (zereg > 0){
        remainder = zereg % 2;
        binary = binary + remainder * base;
        zereg = zereg / 2;
        base = base * 10;
    }
    char buffer[255];
	sprintf(buffer, "%ld", binary);
    unsigned long long temp,number=suuri;
	for (int i=1,len=strlen(buffer); i<len ; i++){
		if(buffer[i]=='0'){
				temp = (number * number)%m;
				number = temp;	
			}
		else if (buffer[i] == '1'){
				temp = (number * number)%m;
				temp = (temp*suuri)%m;
				number = temp;
			}
		}
		return  number;
}
int client(int alpha,int q,int YA){
	int XB = PRIVATE_KEY; //XB < q
	int YB;
	YB = modulo(alpha , XB , q);
	if (YA!=0){
	int tulhuur = modulo(YA,XB,q);
	sprintf(key, "%d", tulhuur);
	}
	return YB;
}

void swap(unsigned char *a, unsigned char *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}
int KSA(char *key, unsigned char *S) {
    int len = strlen(key);
    int j = 0;
    for(int i = 0; i < N; i++)
        S[i] = i;
        
    for(int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;

        swap(&S[i], &S[j]);
    }
    return 0;
}
int PRGA(unsigned char *S, char *plaintext, unsigned char *ciphertext) {

    int i = 0;
    int j = 0;

    for(size_t n = 0, len = strlen(plaintext); n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;
        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];
        ciphertext[n] = rnd ^ plaintext[n];
    }
    return 0;
}

int RC4(char *key, char *plaintext, unsigned char *ciphertext) {

    unsigned char S[N];
    KSA(key, S);

    PRGA(S, plaintext, ciphertext);

    return 0;
}

void error(const char *msg){
	perror(msg); // perror sudal 
	exit(0);
}
void  *read_message(void * socket){
	int sockfd, ret;  
	char buffer[255];   
	sockfd = (int) socket;  
	bzero(buffer, 255 );
	for (;;) 
		{  
		ret = recvfrom(sockfd, buffer, 255, 0, NULL, NULL);    
		if (ret < 0) 
			{    
				 printf("Error receiving data!\n");      
			} 
		 else if(ret > 0)
			{ 	
				//char key[] = "khuslen";
				char buff[255] ; 
				unsigned char *deciphertext = malloc(sizeof(int) * 255);
				RC4(key, buffer , deciphertext);
				for(size_t k = 0, len = strlen(buffer); k < len; k++)
					{
							buff[k] = deciphertext[k];
							
					}	
				printf("server: ");  
				fputs(buff, stdout);  
				bzero(buff, 255);
				bzero(buffer, 255);
			}
		  else if(ret == 0)
			{
				pthread_exit(NULL);
				return 0 ;	
			}
		 } 
}
int main(int argc,char *argv[]){
	if(argc < 2){
		printf("usage: ip:port = 0.0.0.0:*****  \n");
		exit(1);
	}
	if(argc < 3){
		printf("PORT! \n");
		exit(1);
	}
	int sockfd, portNumber ;
	int n;
	pthread_t readID;
	struct sockaddr_in server_addr;
	struct hostent *server;
	
	char buffer[255];
	portNumber = atoi(argv[2]);
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
		error("SOCKET neegdsengui!");

	server = gethostbyname(argv[1]);
	if(server== NULL){
		fprintf(stderr,"error hosgui bn");
	}
	
	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	bcopy((char *) server -> h_addr ,
			(char *) &server_addr.sin_addr.s_addr, server -> h_length);
	server_addr.sin_port = htons(portNumber);
	if (connect (sockfd , (struct sockaddr *) &server_addr, sizeof(server_addr))<0)
		error("holbolt butsengui");
	else
		printf("#*#* >TCP CLIENT OK< #*#*\n\n");
		//HERE KEY
		char serverSEC[255];
		n = recvfrom(sockfd, serverSEC, 255, 0, NULL, NULL);    
		if (n < 0)    
			printf("REC KEY!\n");      
			
		int q = 90863; //prime number
		int alpha = 52864; //α < q and α a primitive root of q
		int YB = client(alpha,q,0);
		char secret[255];
		sprintf(secret, "%d", YB);
		n = write(sockfd, secret, strlen(secret));
		if(n < 0 )
			error("KEY!\n");	
		bzero(secret,255);
		
		
		client	(alpha,q,atoi(serverSEC));

		bzero(secret,255);
			
		
		n = pthread_create(&readID, NULL, read_message, (void *) sockfd);

char data[255];
	//char key[] = "khuslen";
	while(1){
			bzero(buffer, 255);
			bzero(data, 255);
				
			//printf("client :");
			//scanf("%s", data);
			fgets(data,255,stdin);
			unsigned char *ciphertext = malloc(sizeof(int) * strlen(data));
			RC4(key , data ,ciphertext);
			for(int i = 0, length = strlen(data); i < length; i++){
				buffer[i] = ciphertext[i];
				}
			//printf("%s >>" , buffer);
			n = write(sockfd, buffer, strlen(buffer));
			if(n < 0 )
				error("Write hiisengui");
			
			
              
           // bzero(ciphertext, 255);			
	}
	close(sockfd);
	return 0;
}

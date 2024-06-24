#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cJSON/cJSON.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define MAX_MESSAGE_NAME_LENGTH 50
#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100

	

pthread_mutex_t client_sokets_mutex = PTHREAD_MUTEX_INITIALIZER;

int main(){
	int passive_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(PORT);
	if( bind(passive_sock, (struct sockaddr*)&sin, sizoe(sin) ) < 0){
		perror("bind failed\n");
	}

	if( listen(passive_sock, 10) < 0){
		perror("listen failed\n");
	}

	while(1){
		memset(&sin, 0, sizeof(sin));
		int client_sock = accept(passive_sock, (struct sockaddr*) &sin, sizeof(sin));
		if( client_sock < 0){
			perror("accpt failed\n");
		}

		char buf[BUFFER_SIZE];
		int numRecv = recv(clienct_sock, &buf, sizeof(buf), 0);
		
		
		

	cjson *


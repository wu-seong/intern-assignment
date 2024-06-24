#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cjson/cJSON.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define MAX_MESSAGE_NAME_LENGTH 50
#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100
#define EXPECTED_TYPE "PowerUP"
typedef struct {
    int socket;
    struct sockaddr_in address;
} client_t;


bool check_reason(cJSON* reason){
 if (cJSON_IsString(reason) && (reason -> valuestring != NULL)) {
        printf("Reason: %s\n", reason -> valuestring);
		return reason -> valuestring == EXPECTED_TYPE;
    }
}

// 첫 연결 후 실행할 콜백 함수
void* handle_client(void *arg){
	client_t *client = (client_t *)arg;
	char* buffer[BUFFER_SIZE];

	// 요청 메시지 읽기
	int read_bytes = recv(client->socket, &buffer, sizeof(buffer), 0);
	if (read_bytes > 0) {
    	buffer[read_bytes] = '\0'; 
        printf("Received: %s\n", buffer);
		cJSON *json = cJSON_Parse(buffer);
		if(json == NULL){
			perror("JSON parse failed");
		}
		bool is_correct_reason = check_reason(cJSON_GetObjectItemCaseSensitive(json, "reason"));
		// reason이 PowerUp이 아니라면 클라이언트와의 연결 종료 후 다시 클라이언트 연결 대기
		if(!is_correct_reason){
			cJSON_Delete(json);
			close(client->socket);
			free(arg);
			pthread_exit(NULL);
		}
		// chargin station 식별 ...

		// 식별 성공 시 accept

		// response 만들어서 send
		// currentTime(String), status(), inerval 정보 만들어서 JSON serialize

		// 이후로는 heartbeatRequest에 대한 response 전달
	}
	else if(read_bytes == -1){
		perror("recv failed");
	}
	else if(read_bytes == 0){
		printf("client disconnected\n");
	}

	return NULL;
}
	
pthread_mutex_t client_sockets_mutex = PTHREAD_MUTEX_INITIALIZER;
client_t* client_sockets[MAX_CLIENTS];

int main(){
	int passive_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	pthread_t t_id;

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(PORT);
	if(bind(passive_sock, (struct sockaddr*)&sin, sizoe(sin) ) < 0){
		perror("bind failed\n");
	}

	if(listen(passive_sock, 10) < 0){
		perror("listen failed\n");
	}

	while(1){
		memset(&sin, 0, sizeof(sin));
		int client_sock = accept(passive_sock, (struct sockaddr*)&sin, sizeof(sin));
		if(client_sock < 0){
			perror("accpt failed\n");
		}
 		client_t *new_client = (client_t *)malloc(sizeof(client_t));
        new_client->socket = client_sock;
        new_client->address = sin;

		// 관리할 소켓 대상에 추가 및 스레드 생성
		pthread_mutex_lock(&client_sockets_mutex);
		for(int i = 0; i< MAX_CLIENTS; i++){
			if(client_sockets[i] == NULL){
				client_sockets[i] = new_client;
				if(pthread_create(&t_id, NULL, handle_client, &sin) != 0){
					perror("thread create failed");
					close(new_client->socket);
					free(new_client);
					client_sockets[i] = NULL;
				}
				else{
					// 자식 스레드 분리
					pthread_detach(t_id); 
				}
			}
			break;
		}
		pthread_mutex_unlock(&client_sockets_mutex);
	

	}
}
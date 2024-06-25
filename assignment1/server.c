#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define MAX_MESSAGE_NAME_LENGTH 50
#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 100
#define EXPECTED_TYPE "PowerUP"

typedef struct {
    int socket;
    struct sockaddr_in address;
} client_t;


bool check_reason(cJSON* reason){
	if (cJSON_IsString(reason) && (reason -> valuestring != NULL)) {
			printf("Reason: %s\n", reason -> valuestring);
			return strcmp(reason->valuestring, EXPECTED_TYPE) == 0;
	}
}

int get_interval_time(){
    srand(time(NULL));
    int random_number = (rand() % 5) + 1;
	return random_number;
}
char* get_current_time(){
	struct timeval tv;
	struct tm* tm;
	gettimeofday(&tv, NULL);
	tm = gmtime(&tv.tv_sec);  // UTC 시간으로 변환합니다

	char *temp_buffer = (char*)malloc(sizeof(char)*30); 
	// 날짜와 시간을 포맷팅
    strftime(temp_buffer, 20, "%Y-%m-%dT%H:%M:%S", tm);
    printf("%s\n", temp_buffer);
    // 밀리초 추가
	int remaining_size = 30 - strlen(temp_buffer) - 1;
    snprintf(temp_buffer + strlen(temp_buffer), remaining_size, ".%03ldZ", tv.tv_usec / 1000);
	return temp_buffer;
}

char* create_boot_notification_response(){
	cJSON *json_boot_notification_response = cJSON_CreateObject();
	if (json_boot_notification_response == NULL) {
		printf("Error creating JSON\n");
		cJSON_Delete(json_boot_notification_response);
		return NULL;
	}
	char* current_time = get_current_time();
	cJSON_AddStringToObject(json_boot_notification_response, "_type", "BootNotificationResponse");
	cJSON_AddStringToObject(json_boot_notification_response, "_timestamp", current_time);
	cJSON_AddStringToObject(json_boot_notification_response, "currentTime", current_time);
	cJSON_AddNumberToObject(json_boot_notification_response, "interval", get_interval_time());
	cJSON_AddStringToObject(json_boot_notification_response, "status", "Accepted");
	char* json_string =cJSON_PrintUnformatted(json_boot_notification_response);
	cJSON_Delete(json_boot_notification_response);
	return json_string;
}

// 첫 연결 후 실행할 콜백 함수
void* handle_client(void *arg){
	client_t *client = (client_t *)arg;
	char read_buffer[BUFFER_SIZE];

	// 요청 메시지 읽기
	printf("recv wait...");
	int read_bytes = recv(client->socket, &read_buffer, sizeof(read_buffer), 0);
	if (read_bytes > 0) {
    	read_buffer[read_bytes] = '\0'; 
        printf("Server Received: %s\n", read_buffer);
		cJSON *json = cJSON_Parse(read_buffer);
		if(json == NULL){
			perror("JSON parse failed");
		}
		bool is_correct_reason = check_reason(cJSON_GetObjectItemCaseSensitive(json, "reason"));
		// reason이 PowerUp이 아니라면 클라이언트와의 연결 종료 후 다시 클라이언트 연결 대기
		printf("isTrue: %s\n", is_correct_reason ? "true" : "false");
		if(!is_correct_reason){
			cJSON_Delete(json);
			close(client->socket);
			free(arg);
			pthread_exit(NULL);
		}
		// chargin station 식별 ...

		// 식별 성공 시 accept 응답

		// response 만들어서 send
		// currentTime(String), status(), inerval 정보 만들어서 JSON serialize
		char* boot_notification_response = create_boot_notification_response();
		printf("보낼 메시지: %s\n", boot_notification_response);
		if( write(client->socket, boot_notification_response, strlen(boot_notification_response) ) ){
			perror("write failed");
		}
		printf("Server Send: %s\n", boot_notification_response);

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
client_t* client_sockets[MAX_CLIENTS] = {NULL};

int main(){
	int passive_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	pthread_t t_id;

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(PORT);
	if(bind(passive_sock, (struct sockaddr*)&sin, sizeof(sin) ) < 0){
		perror("bind failed\n");
	}

	if(listen(passive_sock, 10) < 0){
		perror("listen failed\n");
	}
	printf("Listening...");

	while(1){
		memset(&sin, 0, sizeof(sin));
		unsigned int sin_len = sizeof(sin);
		int client_sock = accept(passive_sock, (struct sockaddr*)&sin, &sin_len);
		if(client_sock < 0){
			perror("accpt failed\n");
			continue;
		}
		printf("connect\n");
 		client_t *new_client = (client_t *)malloc(sizeof(client_t));
        new_client->socket = client_sock;
        new_client->address = sin;

		// 관리할 소켓 대상에 추가 및 스레드 생성
		pthread_mutex_lock(&client_sockets_mutex);
		for(int i = 0; i< MAX_CLIENTS; i++){
			if(client_sockets[i] == NULL){
				client_sockets[i] = new_client;
				if(pthread_create(&t_id, NULL, handle_client, (void*)new_client) != 0){
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
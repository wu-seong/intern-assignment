#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

#include <cjson/cJSON.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define PORT 8080
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024

#define CERT_CHAIN_FILE "./aslab_certificates/client_cert_chain.pem"
#define KEY_FILE "./aslab_certificates/client_leaf_private.pem"
#define CA_FILE "./aslab_certificates/server_rootca.pem"

void error_handling(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}
char* get_current_time(){
	struct timeval tv;
	struct tm* tm;
	gettimeofday(&tv, NULL);
	tm = gmtime(&tv.tv_sec);  // UTC 시간으로 변환합니다

	char *temp_buffer = (char*)malloc(sizeof(char)*30); 
	// 날짜와 시간을 포맷팅
    strftime(temp_buffer, 20, "%Y-%m-%dT%H:%M:%S", tm);
    // 밀리초 추가
	int remaining_size = 30 - strlen(temp_buffer) - 1;
    snprintf(temp_buffer + strlen(temp_buffer), remaining_size, ".%03ldZ", tv.tv_usec / 1000);
	return temp_buffer;
}

void add_charging_station_type(cJSON* parent, char* serial_number, const char* model, const char* vendor_name, char* firmware_version, char* modem){
    // 일단 require만 사용 (model, vendorName)
    cJSON* json_charging_station_type = cJSON_CreateObject();
    cJSON_AddStringToObject(json_charging_station_type, "model", model);
    cJSON_AddStringToObject(json_charging_station_type, "vendorName", vendor_name);
    cJSON_AddItemToObject(parent, "chargingStation", json_charging_station_type);
}
char* create_boot_notification_request() {
    cJSON *json_boot_notification_request = cJSON_CreateObject();
    if (json_boot_notification_request == NULL) {
        error_handling("Failed to create JSON object");
    }
    cJSON_AddStringToObject(json_boot_notification_request, "_type", "BootNotificationRequest");
    char* current_time = get_current_time();
    cJSON_AddStringToObject(json_boot_notification_request, "_timestamp", current_time);
    cJSON_AddStringToObject(json_boot_notification_request, "reason", "PowerUP");
    add_charging_station_type(json_boot_notification_request, NULL, "newmodel","hyundai", NULL, NULL);
    free(current_time);

    char* buffer = cJSON_PrintUnformatted(json_boot_notification_request);
    if (buffer == NULL) {
        cJSON_Delete(json_boot_notification_request);
        error_handling("Failed to print JSON");
    }
    cJSON_Delete(json_boot_notification_request);
    return buffer;
}
char* create_heartbeat_request(){
     cJSON *json_heartbeat_request = cJSON_CreateObject();
    if (json_heartbeat_request == NULL) {
        error_handling("Failed to create JSON object");
    }
    cJSON_AddStringToObject(json_heartbeat_request, "_type", "HeartbeatRequest");
    char* current_time = get_current_time();
    cJSON_AddStringToObject(json_heartbeat_request, "_timestamp", current_time);
    char* buffer = cJSON_PrintUnformatted(json_heartbeat_request);
    if (buffer == NULL) {
        cJSON_Delete(json_heartbeat_request);
        error_handling("Failed to print JSON");
    }
    return buffer;
}

bool check_status(cJSON* status){
	if (cJSON_IsString(status) && (status -> valuestring != NULL)) {
			//printf("status: %s\n", status -> valuestring);
			return strcmp(status->valuestring, "Accepted") == 0;
	}
}

WOLFSSL_CTX* wolfssl_init(){
	// Create and configure WOLFSSL_CTX
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        perror("wolfSSL_CTX_new() error");
    }

     // Load server certificate chain and key
    if (wolfSSL_CTX_use_certificate_chain_file(ctx, CERT_CHAIN_FILE) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_use_certificate_chain_file() error");
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_use_PrivateKey_file() error");
    }

	// Load root CA certificate for verifying client certificates
    if (wolfSSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_load_verify_locations() error");
    }
    
    // Set cipher suites
    wolfSSL_CTX_set_cipher_list(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
	return ctx;

}
int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];


    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        error_handling("socket() error");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(PORT);

    // 연결에 SSL 적용
    WOLFSSL_CTX* ctx = wolfssl_init();
	WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, sock);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        error_handling("connect() error");
    }

    char* boot_notification_request = create_boot_notification_request();

    int ret = wolfSSL_write(ssl, boot_notification_request, strlen(boot_notification_request) );
    if (ret > 0){
        printf("Sent Message: %s\n", boot_notification_request);
    }
    else{
        int err = wolfSSL_get_error(ssl, ret);

        fprintf(stderr, "wolfSSL_write failed: %d\n", err);
        switch (err) {
        case SSL_ERROR_WANT_READ:
            fprintf(stderr, "SSL_ERROR_WANT_READ: The operation did not complete; the same TLS/SSL I/O function should be called again later.\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            fprintf(stderr, "SSL_ERROR_WANT_WRITE: The operation did not complete; the same TLS/SSL I/O function should be called again later.\n");
            break;
        case SSL_ERROR_SYSCALL:
            fprintf(stderr, "SSL_ERROR_SYSCALL: Some I/O error occurred. The OpenSSL error queue may contain more information on the error.\n");
            break;
        case SSL_ERROR_SSL:
            fprintf(stderr, "SSL_ERROR_SSL: A failure in the SSL library occurred, usually a protocol error.\n");
            break;
        default:
            fprintf(stderr, "Unknown error occurred.\n");
            break;
        }
        perror("wolfSSL_write() error");
    }


    int read_bytes = wolfSSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if(read_bytes == 0){
        char errorString[80];
        int err = wolfSSL_get_error(ssl, 0);
        char* error_string = wolfSSL_ERR_error_string(err, errorString);
        perror(error_string);
        wolfSSL_free(ssl);
        close(sock);
    }
    buffer[read_bytes] = '\0';
    printf("Received Message: %s\n", buffer);
    cJSON *json_boot_notification_response = cJSON_Parse(buffer);
    if(json_boot_notification_response == NULL){
        perror("JSON parse failed");
    }
    bool is_accpted = check_status(cJSON_GetObjectItemCaseSensitive(json_boot_notification_response, "status"));
    
    if(!is_accpted){ // pending or rejected 
        cJSON_Delete(json_boot_notification_response);
        close(sock);
        return 1;
    }

    cJSON* json_interval = cJSON_GetObjectItemCaseSensitive(json_boot_notification_response, "interval");
    struct timeval timeout;
    timeout.tv_sec = json_interval->valueint;
    timeout.tv_usec = 0;
    cJSON_Delete(json_interval);

    while(1){
        char* heartbeat_request = create_heartbeat_request();   
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
            error_handling("setsockopt() error");
        }

       if( wolfSSL_write(ssl, heartbeat_request, strlen(heartbeat_request) ) <= 0 ){
		    perror("write failed");
	    }
        printf("Sent Message: %s\n", heartbeat_request);

        free(heartbeat_request);
        memset(buffer, 0, BUFFER_SIZE);
        int read_bytes = wolfSSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if(read_bytes == 0){
			char errorString[80];
    		int err = wolfSSL_get_error(ssl, 0);
    		char* error_string = wolfSSL_ERR_error_string(err, errorString);
			perror(error_string);
			wolfSSL_free(ssl);
			close(sock);
        } else {
            buffer[read_bytes] = '\0';
            cJSON* json_heartbeaet_response = cJSON_Parse(buffer);
            printf("Received message: %s\n", buffer);
            printf("Server currentTime: %s\n", cJSON_GetObjectItemCaseSensitive(json_heartbeaet_response, "currentTime")->valuestring);
        }
        sleep(timeout.tv_sec); 
    }
    return 0;
}

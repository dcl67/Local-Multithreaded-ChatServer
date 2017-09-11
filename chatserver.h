#ifndef CHATSERVER_H_ 
#define CHATSERVER_H_
#include <pthread.h> 

#define EXIT_COMMAND "-e"
#define EXIT_COMMAND_LEN 2
#define DIRECT_MESSAGE_COMMAND "-dm"
#define DIRECT_MESSAGE_COMMAND_LEN 3

#define MAX_ID_LEN 6
#define MAX_MESSAGE_LEN 50
#define MAX_CLIENTS 10

#define NULL_MESSAGE 0
#define DIRECT_MESSAGE 1
#define GROUP_MESSAGE 2
#define SERVER_MESSAGE 3
#define RESPONSE_MESSAGE 4
#define CLOSE_MESSAGE 5

#define DISCONNECT -1
#define CONNECTED 0
#define CONNECT 1

#define INVALID_RECIPIENT 0

#define SERVER_FULL_MESSAGE "The server is full with MAX_CLIENTS\n"

typedef struct message_packet{
	int roomID;
	int message_type;
	char sender_id[MAX_ID_LEN];
	char receiver_id[MAX_ID_LEN];
	char message[MAX_MESSAGE_LEN];
	int connection;	//Used for adding/removing clients
	pthread_mutex_t* mutex_lock;
}msg_packet_t;

typedef struct group_list{
	char u_id[MAX_ID_LEN];
	int roomID;
}group_list_t;

#endif 

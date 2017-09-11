//server for handling chat clients, messages, groups, direct messages, timeouts, memory allocation, exiting, etc.
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "chatserver.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>

#define MAX_MESSAGE_LENGTH 50
#define MESSAGE_TYPES 8
#define SHARED_PATH "/chat"
//globals
int NumClients;
char Clients[MAX_CLIENTS][MAX_ID_LEN];
group_list_t Groups[MAX_CLIENTS];
int persist;
//struct defs
void send_direct_message(msg_packet_t* sharedMessage);
int valid_recipient(char receiver_id[MAX_ID_LEN]);
void cleanExit(int finished);
void send_group_message(msg_packet_t* sharedMessage);
void wait_for_response(msg_packet_t* sharedMessage);
int connect_client(msg_packet_t* sharedMessage);
int group_contains(int roomID);
void send_error_message(msg_packet_t* sharedMessage, int err);
int disconnect_client(msg_packet_t* sharedMessage);

int main(int argc, char *argv[]) {
	//initialize segment to contain one message and server components
	int sharMem;
	int shared_seg_size=(sizeof(msg_packet_t));
	msg_packet_t* sharedMessage;
	NumClients=0; 
	persist=1;
	signal(SIGINT,cleanExit);

	// Creates shared memory object in /dev/shm
	sharMem=shm_open(SHARED_PATH, O_CREAT | O_EXCL | O_RDWR, S_IRWXU | S_IRWXG); // set permissions for shared object
	if (sharMem < 0) { //checks that you don't have a shared memory object open already
		perror("In shm_open()");
		exit(1);
	}
	fprintf(stderr, "Created shared memory object %s\n", SHARED_PATH);

	// Make room for the whole segment to map using ftruncate()
	ftruncate(sharMem, shared_seg_size);

	//mmap to request shared memory   
	sharedMessage=(msg_packet_t*)mmap(NULL, shared_seg_size, PROT_READ | PROT_WRITE, MAP_SHARED, sharMem, 0);
	if (sharedMessage == NULL) {
		perror("In mmap()");
		exit(1);
	}
	fprintf(stderr, "Shared memory segment allocated correctly (%d bytes).\n", shared_seg_size);
	pthread_mutexattr_t* mutex_attr;
	pthread_mutexattr_init(&mutex_attr);
	pthread_mutexattr_setpshared(&mutex_attr,PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&sharedMessage->mutex_lock,&mutex_attr);
	pthread_mutex_lock(&sharedMessage->mutex_lock);
	sharedMessage->message_type=NULL_MESSAGE;
	pthread_mutex_unlock(&sharedMessage->mutex_lock);
	while(persist){
		pthread_mutex_lock(&sharedMessage->mutex_lock);
		// New Client added
		if(sharedMessage->connection == CONNECT){
			connect_client(sharedMessage);	
			pthread_mutex_unlock(&sharedMessage->mutex_lock);
			continue;
		}

		if(sharedMessage->connection == DISCONNECT){	
			disconnect_client(sharedMessage);
			if(NumClients == 0){
				pthread_mutex_unlock(&sharedMessage->mutex_lock);
				break;
			}
		}
		// Message sent by client
		if(sharedMessage->message_type != NULL_MESSAGE){
			if(sharedMessage->message_type == DIRECT_MESSAGE){
				printf("Recieved message from %s for %s: %s",sharedMessage->sender_id,sharedMessage->receiver_id,sharedMessage->message);
				if(valid_recipient(sharedMessage->receiver_id) == 1){
					pthread_mutex_unlock(&sharedMessage->mutex_lock);
					send_direct_message(sharedMessage);
					pthread_mutex_lock(&sharedMessage->mutex_lock);
				}
				else{
					pthread_mutex_unlock(&sharedMessage->mutex_lock);
					send_error_message(sharedMessage,INVALID_RECIPIENT);
					pthread_mutex_lock(&sharedMessage->mutex_lock);
				}
			}
			if(sharedMessage->message_type == GROUP_MESSAGE){
				printf("Recieved message from %s to group: %s",sharedMessage->sender_id,sharedMessage->message);
				pthread_mutex_unlock(&sharedMessage->mutex_lock);
				send_group_message(sharedMessage);
				pthread_mutex_lock(&sharedMessage->mutex_lock);

			}
			if(sharedMessage->message_type != SERVER_MESSAGE)
				sharedMessage->message_type=NULL_MESSAGE;
		}
		pthread_mutex_unlock(&sharedMessage->mutex_lock);		
	}

	// Remove shared memory
	if (shm_unlink(SHARED_PATH) != 0) {
		perror("In shm_unlink()");
		exit(1);
	}

	return 0;
}
//join room
int connect_client(msg_packet_t* sharedMessage){
	if(NumClients < 10){
		char group_status_msg[MAX_MESSAGE_LEN];
		//check if room doesn't exist
		if(group_contains(sharedMessage->roomID) == 0){
			snprintf(group_status_msg,MAX_MESSAGE_LEN,"Chat group %i not found...\nCreating group %i\n",sharedMessage->roomID,sharedMessage->roomID);
		}
		//join room afterwards, or join room if it exists
		else{
			snprintf(group_status_msg,MAX_MESSAGE_LEN,"Chat group %i joined\n",sharedMessage->roomID);
		}
		strcpy(Groups[NumClients].u_id,sharedMessage->sender_id);
		Groups[NumClients].roomID=sharedMessage->roomID;
		strcpy(Clients[NumClients++],sharedMessage->sender_id);

		strcpy(sharedMessage->receiver_id,sharedMessage->sender_id);
		strcpy(sharedMessage->sender_id,"SERV");
		strcpy(sharedMessage->message,group_status_msg);

		printf("New Connection, Client: %s Group: %d\n",Clients[NumClients-1], sharedMessage->roomID);
	}
	else{
		strcpy(sharedMessage->receiver_id,sharedMessage->sender_id);
		strcpy(sharedMessage->sender_id,"SERV");		
		strcpy(sharedMessage->message,SERVER_FULL_MESSAGE);
		printf("Connection Attemp, Client: %s Group: %d\nServer full... Connection Denied\n",Clients[NumClients-1], sharedMessage->roomID);
	}
	int i;
	sharedMessage->connection=CONNECTED;
	sharedMessage->message_type=SERVER_MESSAGE;
}

int group_contains(int roomID){
	int i;
	for(i=0; i<NumClients; i++){
		if(Groups[i].roomID == roomID)
			return 1;
	}
	return 0;
}
int disconnect_client(msg_packet_t* sharedMessage){
	int i;
	int client_found=-1;
	for(i=0; i<NumClients; i++){
		if(strcmp(Clients[i],sharedMessage->sender_id) == 0){
			strcpy(Clients[i],"     ");
			strcpy(Groups[i].u_id, "     ");
			client_found=i;
			continue;
		}
		if(client_found > -1){
			strcpy(Clients[i-1],Clients[i]);
			Groups[i-1]=Groups[i];
		}
	}
	sharedMessage->connection=CONNECTED;
	sharedMessage->message_type=NULL_MESSAGE;
	NumClients--;
}
//direct messaging handler
void send_direct_message(msg_packet_t* sharedMessage){
	printf("sending direct message\n");
	pthread_mutex_lock(&sharedMessage->mutex_lock);
	printf("recip: %s sender: %s\n",sharedMessage->receiver_id,sharedMessage->sender_id);

	sharedMessage->message_type=SERVER_MESSAGE;
	pthread_mutex_unlock(&sharedMessage->mutex_lock);
	wait_for_response(sharedMessage);
	printf("Response Received\n");
}
//group messaging handler
void send_group_message(msg_packet_t* sharedMessage){
	pthread_mutex_lock(&sharedMessage->mutex_lock);
	printf("Sending group message to group: %d\n",sharedMessage->roomID);
	pthread_mutex_unlock(&sharedMessage->mutex_lock);
	int i;
	for(i=0; i < NumClients; i++){	
		pthread_mutex_lock(&sharedMessage->mutex_lock);
		if(strcmp(sharedMessage->sender_id,Clients[i]) == 0 || sharedMessage->roomID != Groups[i].roomID){	
			pthread_mutex_unlock(&sharedMessage->mutex_lock);
			continue;
		}
		printf("Sent to %s... ", Clients[i]);
		sharedMessage->message_type=SERVER_MESSAGE;
		strcpy(sharedMessage->receiver_id,Clients[i]);
		pthread_mutex_unlock(&sharedMessage->mutex_lock);
		wait_for_response(sharedMessage);
		printf("Response Received\n");
	}
	printf("Sent group message\n");
}

void wait_for_response(msg_packet_t* sharedMessage){
	while(persist){
		pthread_mutex_lock(&sharedMessage->mutex_lock);
		if(sharedMessage->message_type != SERVER_MESSAGE){
			pthread_mutex_unlock(&sharedMessage->mutex_lock);
			break;
		}
		pthread_mutex_unlock(&sharedMessage->mutex_lock);
	}
	pthread_mutex_unlock(&sharedMessage->mutex_lock);
}
//iterate through recipients currently in chat room
int valid_recipient(char receiver_id[MAX_ID_LEN]){
	int i;
	for(i=0; i<NumClients; i++){
		if(strcmp(receiver_id,Clients[i]) == 0)
			return 1;
	}
	printf("Invalid Recipient: %s\n",receiver_id);
	return 0;
}
//general server messaging error handling
void send_error_message(msg_packet_t* sharedMessage, int err){
	pthread_mutex_lock(&sharedMessage->mutex_lock);
	printf("Sending Error Message: %d\n",err);
	if(err == INVALID_RECIPIENT){
		char rec_id[MAX_ID_LEN];
		strcpy(rec_id,sharedMessage->receiver_id);
		strncpy(sharedMessage->receiver_id,sharedMessage->sender_id,MAX_ID_LEN);
		strcpy(sharedMessage->sender_id,"ERROR");
		sharedMessage->message_type=SERVER_MESSAGE;
		snprintf(sharedMessage->message,MAX_MESSAGE_LEN,"Invalid Recipient Entered: %s\n",rec_id);	
		pthread_mutex_unlock(&sharedMessage->mutex_lock);

		wait_for_response(sharedMessage);
		pthread_mutex_lock(&sharedMessage->mutex_lock);
		printf("Response Received\n");
	}
	pthread_mutex_unlock(&sharedMessage->mutex_lock);
}
//Ryan's special code for a special human being
void exit_helper(msg_packet_t* shared_msg){
	int finished=0;
	pthread_mutex_lock(&shared_msg->mutex_lock);
	shared_msg->message_type=CLOSE_MESSAGE;
	pthread_mutex_unlock(&shared_msg->mutex_lock);
	cleanExit(finished);
}
void exit_helper(msg_packet_t* shared_msg);
//end ryan's special code for special humans

//cleanly exit file upon interrupt signal
void cleanExit(int finished){
	persist=0;
}

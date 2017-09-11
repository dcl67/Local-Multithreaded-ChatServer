#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>
#include "chatserver.h"
#include <time.h>
#include <signal.h>
#include <stdio.h>

#define MAX_MESSAGE_LENGTH 50
#define MESSAGE_TYPES 8
#define SHARED_PATH "/chat"      
//globals
int Connected=0;
char user_message[MAX_MESSAGE_LEN];
char dm_rec[MAX_ID_LEN]="";
int persist;
pthread_mutex_t* user_input_mutex;
int MESSAGE_TYPE;
//struct defs
void open_connection(char uid[MAX_ID_LEN], msg_packet_t* sharedMessage, int roomID);
void close_connection(char uid[MAX_ID_LEN], msg_packet_t* sharedMessage, int roomID);
int send_message(msg_packet_t* sharedMessage,char user_message[MAX_MESSAGE_LEN],char sender_id[MAX_ID_LEN], int MESSAGE_TYPE, int roomID);
void* read_user_input(void* args);
void cleanExit(int finished);

int main(int argc, char *argv[]) {
	if(argc<3){ // Check for argument length, exit file if less than 3
		printf("Invalid execution; Usage: ./client <name> <roomID>\n");
		exit(-1);
	}
	char Uid[MAX_ID_LEN];
	int roomID;
	//assign entered input accordingly
	roomID=atoi(argv[2]);
	strcpy(Uid,argv[1]);

	persist=1;
	signal(SIGINT,cleanExit);
	int sharMem;
	int shared_seg_size=(sizeof(msg_packet_t));   //shared segment stores one message
	msg_packet_t* sharedMessage;


	// Creates shared memory object in /dev/shm
	sharMem=shm_open(SHARED_PATH, O_RDWR, S_IRWXU | S_IRWXG); //set permissions for object
	if (sharMem < 0) {
		perror("Server is not running");//In shm_open()");
		exit(1);
	}
	printf("Opened shared memory object %s\n", SHARED_PATH);

	//mmap to request shared memory   
	sharedMessage=(struct msg_packet_t*)mmap(NULL, shared_seg_size, PROT_READ | PROT_WRITE, MAP_SHARED, sharMem, 0);
	if (sharedMessage == NULL) {
		perror("In mmap()");
		exit(1);
	}
	// Open Connection
	open_connection(Uid,sharedMessage,roomID);
	pthread_t* user_input_thread;
	strcpy(user_message,"");
	//multithreading
	pthread_mutex_init(&user_input_mutex,NULL);
	int rc=pthread_create(&user_input_thread,NULL,read_user_input,(void*) NULL);
	MESSAGE_TYPE=GROUP_MESSAGE;

	while(persist){ // Listen for incoming messages
		pthread_mutex_lock(&sharedMessage->mutex_lock);

		if(sharedMessage->message_type == SERVER_MESSAGE){	//Messaging code
			int match;
			match=strcmp(sharedMessage->receiver_id,Uid);
			if(match == 0){
				printf("%s: %s",sharedMessage->sender_id,sharedMessage->message);
				sharedMessage->message_type=RESPONSE_MESSAGE;
				if(strcmp(sharedMessage->message,SERVER_FULL_MESSAGE)==0)
					persist=0;
			}
		}
		pthread_mutex_unlock(&sharedMessage->mutex_lock); // Prevent overlapping messages if simultaneously sent

		// Read user input and send message
		pthread_mutex_lock(&user_input_mutex);
		if(strcmp(user_message,"") != 0){
			if(send_message(sharedMessage,user_message,Uid, MESSAGE_TYPE,roomID) == 1)
				strcpy(user_message,"");
		} 
		pthread_mutex_unlock(&user_input_mutex); // Prevent overlapping messages if simultaneously sent

		if (sharedMessage->message_type==CLOSE_MESSAGE)
			break;
	}
	close_connection(Uid,sharedMessage,roomID); // Close connection
	return 0;
}
void open_connection(char Uid[MAX_ID_LEN], msg_packet_t* sharedMessage, int roomID){ // Continuously try to connect, then exit after connection runs once
	int is_connected;
	is_connected =CONNECT;
	while(is_connected != CONNECTED && persist){
		pthread_mutex_lock(&sharedMessage->mutex_lock);
		if(sharedMessage->message_type != NULL_MESSAGE){
			pthread_mutex_unlock(&sharedMessage->mutex_lock);
			continue;
		}
		sharedMessage->message_type=SERVER_MESSAGE;
		strcpy(sharedMessage->sender_id, Uid);
		sharedMessage->roomID=roomID;
		strcpy(sharedMessage->receiver_id,"");
		sharedMessage->connection=CONNECT;
		is_connected=CONNECTED;

		pthread_mutex_unlock(&sharedMessage->mutex_lock);
	}
}

void* read_user_input(void* args)
{
	int user_message_set;
	char* rec;
	rec=(char*) malloc(sizeof(char)* MAX_ID_LEN);
	while(persist){
		char temp_message[MAX_MESSAGE_LEN];
		fgets(temp_message,MAX_MESSAGE_LEN,stdin);
		if(strncmp(temp_message,EXIT_COMMAND,EXIT_COMMAND_LEN) == 0)
			break;
		if(strncmp(temp_message,DIRECT_MESSAGE_COMMAND,DIRECT_MESSAGE_COMMAND_LEN) == 0){
			printf("Enter recipient for direct message: ");
			gets(rec);

			printf("Enter Message: ");
			fgets(temp_message,MAX_MESSAGE_LEN,stdin);

			MESSAGE_TYPE=DIRECT_MESSAGE;
		}
		else{
			MESSAGE_TYPE=GROUP_MESSAGE;
		}
		user_message_set=1;
		while(user_message_set && persist){
			pthread_mutex_lock(&user_input_mutex);
			if(strcmp(user_message,"") == 0){
				strcpy(&dm_rec,rec);
				strcpy(user_message,temp_message);
				user_message_set=0;
			}
			pthread_mutex_unlock(&user_input_mutex);
		}
	}
	persist=0;
}
int send_message(msg_packet_t* sharedMessage,char user_message[MAX_MESSAGE_LEN],char sender_id[MAX_ID_LEN], int MESSAGE_TYPE, int roomID){
	int msg_type;
	msg_type =SERVER_MESSAGE;
	while(persist){
		pthread_mutex_lock(&sharedMessage->mutex_lock);
		if(sharedMessage->message_type == NULL_MESSAGE){
			strcpy(sharedMessage->receiver_id,dm_rec);
			sharedMessage->roomID=roomID;
			strcpy(sharedMessage->sender_id,sender_id);
			strncpy(sharedMessage->message,user_message,MAX_MESSAGE_LEN);
			sharedMessage->message_type=MESSAGE_TYPE;
			pthread_mutex_unlock(&sharedMessage->mutex_lock);
			return 1;
		}
		if(sharedMessage->message_type == SERVER_MESSAGE){
			pthread_mutex_unlock(&sharedMessage->mutex_lock);
			return 0;
		}
		pthread_mutex_unlock(&sharedMessage->mutex_lock);
	}	
}

void close_connection(char Uid[MAX_ID_LEN], msg_packet_t* sharedMessage, int roomID)
{
	unsigned int time_out;
	time_out=2;
	int is_connected;
	is_connected=CONNECTED;
	while(is_connected == CONNECTED || time_out != 1){
		time_out++;
		pthread_mutex_lock(&sharedMessage->mutex_lock);
		if(sharedMessage->message_type != NULL_MESSAGE){
			pthread_mutex_unlock(&sharedMessage->mutex_lock);
			continue;
		}

		sharedMessage->message_type=SERVER_MESSAGE;
		strcpy(sharedMessage->sender_id, Uid);
		sharedMessage->roomID=roomID;
		strcpy(sharedMessage->receiver_id,"");
		sharedMessage->connection=DISCONNECT;
		is_connected=DISCONNECT;

		pthread_mutex_unlock(&sharedMessage->mutex_lock);

		if(!persist)
			break;
	}
	if(time_out == 0)
		printf("Timeout on disconnect");

}
//cleanly exit the program
void cleanExit(int finished){
	persist=0;
	exit(0);
}

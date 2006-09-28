//////////////////////////////////////////////////////////////////////
// OTAdmin
//////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//////////////////////////////////////////////////////////////////////

#include <iostream>
#include <stdio.h>
#include <list>

#include "definitions.h"

#include "commands.h"
#include "networkmessage.h"

struct CommandLine
{
	CommandFunc function;
	char* params;
};

CommandLine* parseLine(char* line);
CommandFunc getCommand(char* name, bool internal = false);

typedef std::list<CommandLine*> COMMANDS_QUEUE;


COMMANDS_QUEUE commands_queue;
long next_command_delay = 0;
SOCKET g_socket = SOCKET_ERROR;
bool g_connected = false;

CommandFunc disconnect_function;
CommandFunc ping_function;

int main()
{
#if defined WIN32 || defined __WINDOWS__
	WSADATA wsd;
	if(WSAStartup(MAKEWORD(2,2), &wsd) != 0){
		return 1;
	}
#endif

	disconnect_function = getCommand("disconnect", true);
	ping_function = getCommand("ping", true);

	char command[1024];
	long lineCounter = 0;
	long exit_code = 0;
	while(!std::cin.eof()){
		lineCounter++;
		std::cin.getline(command, 1024);
		if(strcmp(command, "") != 0){
			//comments line
			if(command[0] == '#'){
				continue;
			}
			//lower case until first space
			for(int i = 0; i < strlen(command) && command[i] != ' '; ++i){
				command[i] = tolower(command[i]);
				if(command[i] == '\r'){
					command[i] = 0;
					break;
				}
			}
			
			if(strlen(command) == 0)
				continue;
			
			CommandLine* commandLine;
			if(commandLine = parseLine(command)){
				commands_queue.push_back(commandLine);
			}
			else{
				std::cout << "Syntax error in line " << lineCounter << " " << command << std::endl;
				//clear commands
				COMMANDS_QUEUE::iterator it;
				for(it = commands_queue.begin(); it != commands_queue.end(); ++it){
					delete[] (*it)->params;
					delete *it;
				}
				commands_queue.clear();
				return 1;
			}
		}
	}

	//execute commands now
	NetworkMessage msg;
	COMMANDS_QUEUE::iterator it = commands_queue.begin();
	long last_ping = 0;
	while(it != commands_queue.end()){
		if(g_connected){
			//check socket state
			//select(...)
			if(msg.ReadFromSocket(g_socket)){
				//parse it
				//just can recieve AP_MSG_MESSAGE or AP_MSG_ERROR
			}
		}
		OTSYS_SLEEP(250);
		last_ping = last_ping + 250;
		if(next_command_delay > 250){
			next_command_delay = next_command_delay - 250;
		}
		else{
			next_command_delay = 0;
			//execute the command
			if((*it)->function((*it)->params) == 1){
				//everything was ok
				++it;
			}
			else{
				//error in the command
				exit_code  = 1;
				break;
			}
		}
		if(last_ping > 40000){
			//send ping here
			ping_function(NULL);
			last_ping = 0;
		}
	}
	//if connected end the connection
	if(g_connected){
		disconnect_function(NULL);
	}

	//free it
	for(it = commands_queue.begin(); it != commands_queue.end(); ++it){
		delete[] (*it)->params;
		delete *it;
	}
	commands_queue.clear();
#if defined WIN32 || defined __WINDOWS__
	WSACleanup();
#endif
	return exit_code;
}


CommandLine* parseLine(char* line)
{
	char* command = NULL;
	char* params = NULL;
	for(int i = 0; i < strlen(line); i++){
		if(line[i] == ' '){
			command = line;
			line[i] = 0;
			params = &line[i + 1];
			break;
		}
	}
	if(command == NULL){
		command = line;
	}
	
	CommandFunc f = getCommand(command);
	if(f){
		CommandLine* cLine = new CommandLine;
		cLine->function = f;
		char* tmp_params;
		if(params){
			int n = strlen(params);
			if(n > 0){
				tmp_params = new char[n + 1];
				strcpy(tmp_params, params);
			}
			else{
				tmp_params = NULL;
			}
		}
		else{
			tmp_params = NULL;
		}
		cLine->params = tmp_params;
		return cLine;
	}
	return NULL;
}


CommandFunc getCommand(char* name,  bool internal)
{
	defcommands* list = getCommadsList();
	for(int i = 0;  list[i].f != NULL; ++i){
		if(!internal){
			if(strcmp(list[i].name, "LAST") == 0){
				break;
			}
		}
		if(strcmp(list[i].name, name) == 0){
			return list[i].f;
		}
	}
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// OTAdmin - OpenTibia
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
#include <string>

#include "commands.h"
#include "networkmessage.h"
#include "rsa.h"

extern long next_command_delay;
extern SOCKET g_socket;
extern bool g_connected;

bool sendCommand(char commandByte, char* command);
bool sendMsg(NetworkMessage& msg, uint32_t* key = NULL);

std::string serverHost;
uint16_t serverPort;

//server localhost 7171
int setServer(char* params)
{
	char host[256];
	int port;
	if(strlen(params) > 255){
		std::cerr << "[server] too long host and port" << std::endl;
		return -1;
	}
	if(sscanf(params, "%s %d", &host, &port) != 2){
		std::cerr << "[server] no valid host or port" << std::endl;
		return -1;
	}
	else{
		serverHost = host;
		serverPort = port;
		return 1;
	}
}

//connect test
int cmdConnect(char* params)
{
	if(g_connected == true){
		std::cerr << "[connect] already connected" << std::endl;
		return -1;
	}

	char password[128];
	if(strlen(params) > 127){
		std::cerr << "[connect] too long password" << std::endl;
		return -1;
	}
	if(sscanf(params, "%s", &password) != 1){
		std::cerr << "[connect] no valid password" << std::endl;
		return -1;
	}

	g_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	uint32_t remote_ip = inet_addr(serverHost.c_str());
	if(remote_ip == INADDR_NONE){
		struct hostent* hp = gethostbyname(serverHost.c_str());
		if(hp != 0){
			remote_ip = *(long*)hp->h_addr;
		}
		else{
			closesocket(g_socket);
			std::cerr << "[connect] can not resolve server host" << std::endl;
			return -1;
		}
	}

	sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = remote_ip;
	serveraddr.sin_port = htons(serverPort);

	if(connect(g_socket, (SOCKADDR*)&serveraddr, sizeof(serveraddr)) == SOCKET_ERROR){
		closesocket(g_socket);
		std::cerr << "[connect] can not connect to server " << serverHost << std::endl;
		return -1;
	}
	std::cout << "Connected to " << serverHost << std::endl;

	NetworkMessage msg;
	msg.AddByte(0xFE);
	if(!msg.WriteToSocket(g_socket)){
		closesocket(g_socket);
		std::cerr << "[connect] error while sending first byte"<< std::endl;
		return -1;
	}
	msg.Reset();
	//read server hello

	if(!msg.ReadFromSocket(g_socket)){
		closesocket(g_socket);
		std::cerr << "[connect] error while reading hello"<< std::endl;
		return -1;
	}

	char byte = msg.GetByte();
	if(byte != AP_MSG_HELLO){
		closesocket(g_socket);
		std::cerr << "[connect] no valid server hello"<< std::endl;
		return -1;
	}
	msg.GetU32();
	std::string strversion = msg.GetString();
	std::cout << "Hello from " << strversion << std::endl ;
	uint16_t security = msg.GetU16();
	uint32_t options = msg.GetU32();

	//set encryption
	if(security & REQUIRE_ENCRYPTION){
		if(options & ENCRYPTION_RSA1024XTEA){
			//get public key
			msg.Reset();
			msg.AddByte(AP_MSG_KEY_EXCHANGE);
			msg.AddByte(ENCRYPTION_RSA1024XTEA);

			if(!sendMsg(msg)){
				closesocket(g_socket);
				std::cerr << "[connect] error while getting public key"<< std::endl;
				return -1;
			}

			char ret_code = msg.GetByte();
			if(ret_code == AP_MSG_KEY_EXCHANGE_OK){
				std::cout << "Key exchange OK" << std::endl;
			}
			else if(ret_code == AP_MSG_KEY_EXCHANGE_FAILED){
				std::string error_desc = msg.GetString();
				closesocket(g_socket);
				std::cerr << "[connect] can not get public key: " << error_desc << std::endl;
				return -1;
			}
			else{
				closesocket(g_socket);
				std::cerr << "[connect] not known response to key exchange request" << std::endl;
				return -1;
			}

			unsigned char key_type = msg.GetByte();
			if(key_type != ENCRYPTION_RSA1024XTEA){
				closesocket(g_socket);
				std::cerr << "[connect] no valid key returned" << std::endl;
				return -1;
			}
			
			//the public key is 128 bytes
			uint32_t rsa_mod[32];
			for(unsigned int i = 0; i < 32; ++i){
				rsa_mod[i] = msg.GetU32();
			}
			RSA::getInstance()->setPublicKey((char*)rsa_mod, "65537");

			
			uint32_t random_key[32];
			for(unsigned int i = 0; i < 32; ++i){
				random_key[i] = 0x1111112;
			}
			
			msg.setRSAInstance(RSA::getInstance());
			msg.Reset();
			msg.AddByte(AP_MSG_ENCRYPTION);
			msg.AddByte(ENCRYPTION_RSA1024XTEA);
			//build the 128 bytes block
			msg.AddByte(0);
			for(unsigned int i = 0; i < 31; ++i){
				msg.AddU32(random_key[i]);
			}
			msg.AddByte(0);
			msg.AddByte(0);
			msg.AddByte(0);
			//
			msg.RSA_encrypt();

			if(!sendMsg(msg, random_key)){
				closesocket(g_socket);
				std::cerr << "[connect] error while sending private key"<< std::endl;
				return -1;
			}

			ret_code = msg.GetByte();
			if(ret_code == AP_MSG_ENCRYPTION_OK){
				std::cout << "Encryption OK" << std::endl;
			}
			else if(ret_code == AP_MSG_ENCRYPTION_FAILED){
				std::string error_desc = msg.GetString();
				closesocket(g_socket);
				std::cerr << "[connect] can not set private key: " << error_desc << std::endl;
				return -1;
			}
			else{
				closesocket(g_socket);
				std::cerr << "[connect] not known response to set private key request" << std::endl;
				return -1;
			}
			
		}
		else{
			closesocket(g_socket);
			std::cerr << "[connect] can not initiate encryption"<< std::endl;
			return -1;
		}
	}

	
	//login
	if(security & REQUIRE_LOGIN){
		msg.Reset();
		msg.AddByte(AP_MSG_LOGIN);
		msg.AddString(std::string(password));

		if(!sendMsg(msg)){
			closesocket(g_socket);
			std::cerr << "[connect] error while sending login"<< std::endl;
			return -1;
		}

		char ret_code = msg.GetByte();
		if(ret_code == AP_MSG_LOGIN_OK){
			std::cout << "Login OK" << std::endl;
		}
		else if(ret_code == AP_MSG_LOGIN_FAILED){
			std::string error_desc = msg.GetString();
			closesocket(g_socket);
			std::cerr << "[connect] can not login: " << error_desc << std::endl;
			return -1;
		}
		else{
			closesocket(g_socket);
			std::cerr << "[connect] not known response to login request" << std::endl;
			return -1;
		}
	}

	g_connected = true;

	return 1;
}

//disconnect
int cmdDisconnect(char* params)
{
	if(g_connected != true){
		std::cerr << "[disconnect] no connected"<< std::endl;
		return 1;
	}

	closesocket(g_socket);
	g_socket = SOCKET_ERROR;

	std::cout << "Disconnected" << std::endl;
	g_connected = false;
	return 1;
}

//sleep 10000
int sleep(char* params)
{
	int delay;
	if(sscanf(params, "%d", &delay) != 1){
		std::cerr << "[sleep] no valid delay" << std::endl;
		return -1;
	}
	else{
		next_command_delay = delay;
		std::cout << "Sleeping " << delay << " ms" << std::endl;
		return 1;
	}
}

//broadcast hello all
int commandBroadcast(char* params)
{
	if(g_connected != true){
		std::cerr << "[broadcast] no connected"<< std::endl;
		return -1;
	}

	if(!params){
		std::cerr << "[broadcast] no params"<< std::endl;
		return -1;
	}

	long n = strlen(params);
	if(n > 127 || n == 0){
		std::cerr << "[broadcast] no valid params"<< std::endl;
		return -1;
	}

	char message[128];
	strcpy(message, params);

	std::cout << "Broadcast: " << message << std::endl;

	if(!sendCommand(CMD_BROADCAST, message)){
		std::cerr << "[broadcast] error sending broadcast"<< std::endl;
		return -1;
	}

	return 1;
}

//closeserver
int commandCloseServer(char* params)
{
	if(g_connected != true){
		std::cerr << "[closeserver] no connected"<< std::endl;
		return -1;
	}

	if(params){
		std::cerr << "[closeserver] Warning: params ignored"<< std::endl;
	}


	std::cout << "Closing server." << std::endl;

	if(!sendCommand(CMD_CLOSE_SERVER, NULL)){
		std::cerr << "[closeserver] error closing server"<< std::endl;
		return -1;
	}

	return 1;
}

//shutdown
int commandShutdown(char* params)
{
	if(g_connected != true){
		std::cerr << "[shutdown] no connected"<< std::endl;
		return -1;
	}

	if(params){
		std::cerr << "[shutdown] Warning: params ignored"<< std::endl;
	}


	std::cout << "Server shutdown." << std::endl;

	if(!sendCommand(CMD_SHUTDOWN_SERVER, NULL)){
		std::cerr << "[shutdown] error in server shutdown"<< std::endl;
		return -1;
	}

	return 1;
}


//internal use
int ping(char* params)
{
	if(g_connected != true){
		std::cerr << "[ping] no connected"<< std::endl;
		return -1;
	}

	NetworkMessage msg;
	msg.AddByte(AP_MSG_PING);

	if(!sendMsg(msg)){
		std::cerr << "[ping] error sending ping"<< std::endl;
		return -1;
	}

	char ret_code = msg.GetByte();
	if(ret_code != AP_MSG_PING_OK){
		std::cerr << "[ping] no valid ping"<< std::endl;
		return -1;
	}
	return 1;
}

//dummy function
int last(char* params)
{
	std::cout << "[last] you should not be here!!" << std::endl;
	return 1;
}

//help functions

bool sendCommand(char commandByte, char* command)
{
	NetworkMessage msg;
	msg.AddByte(AP_MSG_COMMAND);
	msg.AddByte(commandByte);
	if(command){
		msg.AddString(command);
	}

	if(!sendMsg(msg)){
		std::cerr << "[sendCommand] error while sending command" << std::endl;
		return false;
	}

	char ret_code = msg.GetByte();
	if(ret_code == AP_MSG_COMMAND_OK){
		return true;
	}
	else if(ret_code == AP_MSG_COMMAND_FAILED){
		std::string error_desc = msg.GetString();
		std::cerr << "[sendCommand] error: " << error_desc << std::endl;
		return false;
	}
	else{
		std::cerr << "[sendCommand] no known return code"<< std::endl;
		return false;
	}
}

bool sendMsg(NetworkMessage& msg, uint32_t* key /*= NULL*/)
{
#if defined WIN32 || defined __WINDOWS__
	// Set the socket I/O mode; iMode = 0 for blocking; iMode != 0 for non-blocking
	unsigned long mode = 0;
	ioctlsocket(g_socket, FIONBIO, &mode);
#else
	int flags = fcntl(g_socket, F_GETFL);
	fcntl(g_socket, F_SETFL, flags & (~O_NONBLOCK));
#endif
	bool ret = true;

	if(!msg.WriteToSocket(g_socket)){
		std::cerr << "[sendMsg] error while sending" << std::endl;
		ret = false;
	}

	msg.Reset();

	if(ret){
		if(key){
			msg.setEncryptionState(true);
			msg.setEncryptionKey(key);
		}
		if(!msg.ReadFromSocket(g_socket)){
			std::cerr << "[sendMsg] error while reading" << std::endl;
			ret = false;
		}
		else{
			char ret_code = msg.InspectByte();
			if(ret_code == AP_MSG_ERROR){
				msg.GetByte();
				std::string error_desc = msg.GetString();
				std::cerr << "[sendMsg] MSG_ERROR: " << error_desc << std::endl;
				ret = false;
			}
		}
	}

#if defined WIN32 || defined __WINDOWS__
	mode = 1;
	ioctlsocket(g_socket, FIONBIO, &mode);
#else
	flags = fcntl(g_socket, F_GETFL);
	fcntl(g_socket, F_SETFL, flags | O_NONBLOCK);
#endif
	return ret;
}


//commands list

defcommands commands[] = {
	{"server", &setServer},
	{"connect", &cmdConnect},
	{"sleep", &sleep},
	{"broadcast", &commandBroadcast},
	{"closeserver", &commandCloseServer},
	{"shutdown", &commandShutdown},
	{"disconnect", &cmdDisconnect},
	{"LAST", &last},
	//internal commands
	{"ping", &ping},
	{"", NULL},
};

defcommands* getCommadsList()
{
	return commands;
}

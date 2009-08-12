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

#ifndef __OTADMIN_COMMANDS_H__
#define __OTADMIN_COMMANDS_H__

#include "definitions.h"

typedef int (*CommandFunc)(char* params);

struct defcommands{
	char *name;
	CommandFunc f;
};

defcommands* getCommadsList();


enum{
	//
	AP_MSG_LOGIN = 1,
	AP_MSG_ENCRYPTION = 2,
	AP_MSG_KEY_EXCHANGE = 3,
	AP_MSG_COMMAND = 4,
	AP_MSG_PING = 5,
	AP_MSG_KEEP_ALIVE = 6,
	//
	AP_MSG_HELLO = 1,
	AP_MSG_KEY_EXCHANGE_OK = 2,
	AP_MSG_KEY_EXCHANGE_FAILED = 3,
	AP_MSG_LOGIN_OK = 4,
	AP_MSG_LOGIN_FAILED = 5,
	AP_MSG_COMMAND_OK = 6,
	AP_MSG_COMMAND_FAILED = 7,
	AP_MSG_ENCRYPTION_OK = 8,
	AP_MSG_ENCRYPTION_FAILED = 9,
	AP_MSG_PING_OK = 10,
	AP_MSG_MESSAGE = 11,
	AP_MSG_ERROR = 12,
};

enum{
	CMD_BROADCAST = 1,
	CMD_CLOSE_SERVER = 2,
	CMD_PAY_HOUSES = 3,
	//CMD_OPEN_SERVER = 4,
	CMD_SHUTDOWN_SERVER = 5,
	//CMD_RELOAD_SCRIPTS = 6,
	//CMD_PLAYER_INFO = 7,
	//CMD_GETONLINE = 8,
	CMD_KICK = 9,
	//CMD_BAN_MANAGER = 10,
	//CMD_SERVER_INFO = 11,
	//CMD_GETHOUSE = 12,
	CMD_SAVE_SERVER = 13,
	CMD_SEND_MAIL = 14,
	CMD_SHALLOW_SAVE_SERVER = 15,
	CMD_RELATIONAL_SAVE_SERVER = 16,
};


enum{
	REQUIRE_LOGIN = 1,
	REQUIRE_ENCRYPTION = 2,
};

enum{
	ENCRYPTION_RSA1024XTEA = 1,
};


#endif

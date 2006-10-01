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

#include <string>
#include <iostream>
#include <sstream>

#include "definitions.h"

#include "networkmessage.h"


bool NetworkMessage::m_encryptionEnabled = false;
bool NetworkMessage::m_keyset = false;
uint32_t NetworkMessage::m_key[4] = {0};
RSA* NetworkMessage::m_RSA = NULL;

/******************************************************************************/

NetworkMessage::NetworkMessage()
{
	Reset();
}

NetworkMessage::~NetworkMessage()
{
	//
}

void NetworkMessage::setRSAInstance(RSA* rsa)
{
	m_RSA = rsa;
}

/******************************************************************************/

void NetworkMessage::Reset()
{
	m_MsgSize = 0;
	m_ReadPos = 4;
}


/******************************************************************************/

bool NetworkMessage::ReadFromSocket(SOCKET socket)
{
	// just read the size to avoid reading 2 messages at once
	m_MsgSize = recv(socket, (char*)m_MsgBuf, 2, 0);
	
	// for now we expect 2 bytes at once, it should not be splitted
	int datasize = m_MsgBuf[0] | m_MsgBuf[1] << 8;
	if((m_MsgSize != 2) || (datasize > NETWORKMESSAGE_MAXSIZE-2)){
		int errnum;
#if defined WIN32 || defined __WINDOWS__
		errnum = ::WSAGetLastError();
#else
		errnum = errno;
#endif
		if(errnum == EWOULDBLOCK){
			m_MsgSize = 0;
			return true;
		}

		Reset();
		return false;
	}

	// read the real data
	m_MsgSize += recv(socket, (char*)m_MsgBuf+2, datasize, 0);

	// we got something unexpected/incomplete
	if((m_MsgSize <= 2) || ((m_MsgBuf[0] | m_MsgBuf[1] << 8) != m_MsgSize-2)){
		Reset();
		return false;
	}
	m_ReadPos = 2;
	//decrypt
	if(m_encryptionEnabled){
		if(!m_keyset){
			std::cout << "Failure: [NetworkMessage::ReadFromSocket]. Key not set" << std::endl;
			return false;
		}
		if((m_MsgSize - 2) % 8 != 0){
			std::cout << "Failure: [NetworkMessage::ReadFromSocket]. Not valid encrypted message size" << std::endl;
			return false;
		}
		XTEA_decrypt();
		int tmp = GetU16();
		if(tmp > m_MsgSize - 4){
			std::cout << "Failure: [NetworkMessage::ReadFromSocket]. Not valid unencrypted message size" << std::endl;
			return false;
		}
		m_MsgSize = tmp;
	}
	return true;
}


bool NetworkMessage::WriteToSocket(SOCKET socket)
{
	if (m_MsgSize == 0)
		return true;

	m_MsgBuf[2] = (unsigned char)(m_MsgSize);
	m_MsgBuf[3] = (unsigned char)(m_MsgSize >> 8);
  
	bool ret = true;
	int sendBytes = 0;
	int flags = 0;
	int retry = 0;
	
	int start;
	if(m_encryptionEnabled){
		if(!m_keyset){
			std::cout << "Failure: [NetworkMessage::ReadFromSocket]. Key not set" << std::endl;
			return false;
		}
		start = 0;
		XTEA_encrypt();
	}
	else{
		start = 2;
	}
	
  	do{
		int b = send(socket, (char*)m_MsgBuf + sendBytes + start, std::min(m_MsgSize-sendBytes+2, 1000), flags);
		if(b <= 0){
			int errnum;
#if defined WIN32 || defined __WINDOWS__
			errnum = ::WSAGetLastError();
#else
			errnum = errno;
#endif
			if(errnum == EWOULDBLOCK){
				b = 0;
				OTSYS_SLEEP(10);
				retry++;
				if(retry == 10){
					ret = false;
					break;
				}
			}
			else
			{
				ret = false;
				break;
			}
		}
    	sendBytes += b;
	}while(sendBytes < m_MsgSize+2);

	return ret;
}


/******************************************************************************/

uint8_t NetworkMessage::InspectByte()
{
	return m_MsgBuf[m_ReadPos];
}

uint8_t NetworkMessage::GetByte()
{
	return m_MsgBuf[m_ReadPos++];
}


uint16_t NetworkMessage::GetU16()
{
	uint16_t v = *(uint16_t*)(m_MsgBuf + m_ReadPos);
	m_ReadPos += 2;
	return v;
}

uint32_t NetworkMessage::GetU32()
{
	uint32_t v = *(uint32_t*)(m_MsgBuf + m_ReadPos);
	m_ReadPos += 4;
	return v;
}


std::string NetworkMessage::GetString()
{
	uint16_t stringlen = GetU16();
	if(stringlen >= (16384 - m_ReadPos))
		return std::string();

	char* v = (char*)(m_MsgBuf + m_ReadPos);
	m_ReadPos += stringlen;
	return std::string(v, stringlen);
}

std::string NetworkMessage::GetRaw()
{
	uint16_t stringlen = m_MsgSize- m_ReadPos;
	if(stringlen >= (16384 - m_ReadPos))
		return std::string();

	char* v = (char*)(m_MsgBuf + m_ReadPos);
	m_ReadPos += stringlen;
	return std::string(v, stringlen);
}

void NetworkMessage::SkipBytes(int count)
{
	m_ReadPos += count;
}


/******************************************************************************/


void NetworkMessage::AddByte(uint8_t value)
{
	if(!canAdd(1))
		return;
	m_MsgBuf[m_ReadPos++] = value;
	m_MsgSize++;
}


void NetworkMessage::AddU16(uint16_t value)
{
	if(!canAdd(2))
		return;
	
	*(uint16_t*)(m_MsgBuf + m_ReadPos) = value;
	m_ReadPos += 2;
	m_MsgSize += 2;
}


void NetworkMessage::AddU32(uint32_t value)
{
	if(!canAdd(4))
		return;
	
	*(uint32_t*)(m_MsgBuf + m_ReadPos) = value;
	m_ReadPos += 4;
	m_MsgSize += 4;
}


void NetworkMessage::AddString(const std::string &value)
{
	AddString(value.c_str());
}


void NetworkMessage::AddString(const char* value)
{
	uint32_t stringlen = (uint32_t)strlen(value);
	if(!canAdd(stringlen+2) || stringlen > 8192)
		return;
	
	AddU16(stringlen);
	strcpy((char*)(m_MsgBuf + m_ReadPos), value);
	m_ReadPos += stringlen;
	m_MsgSize += stringlen;
}


/******************************************************************************/

void NetworkMessage::setEncryptionState(bool state)
{
	m_encryptionEnabled = state;
}

void NetworkMessage::setEncryptionKey(const uint32_t* key)
{
	memcpy(m_key, key, 16);
	m_keyset = true;
}


void NetworkMessage::XTEA_encrypt()
{
	uint32_t k[4];
	k[0] = m_key[0]; k[1] = m_key[1]; k[2] = m_key[2]; k[3] = m_key[3];
	
	//add bytes until reach 8 multiple
	uint32_t n;
	if(((m_MsgSize + 2) % 8) != 0){
		n = 8 - ((m_MsgSize + 2) % 8);
		memset((void*)&m_MsgBuf[m_ReadPos], 0, n);
		m_MsgSize = m_MsgSize + n;
	}
	
	unsigned long read_pos = 0;
	uint32_t* buffer = (uint32_t*)&m_MsgBuf[2];
	while(read_pos < m_MsgSize/4){
		uint32_t v0 = buffer[read_pos], v1 = buffer[read_pos + 1];
		uint32_t delta = 0x61C88647;
		uint32_t sum = 0;
		
		for(long i = 0; i<32; i++) {
			v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
			sum -= delta;
			v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum>>11 & 3]);
		}
		buffer[read_pos] = v0; buffer[read_pos + 1] = v1;
		read_pos = read_pos + 2;
	}
	m_MsgSize = m_MsgSize + 2;
	
	*(uint16_t*)(m_MsgBuf) = m_MsgSize;
}

void NetworkMessage::XTEA_decrypt()
{
	uint32_t k[4];
	k[0] = m_key[0]; k[1] = m_key[1]; k[2] = m_key[2]; k[3] = m_key[3];
	
	uint32_t* buffer = (uint32_t*)&m_MsgBuf[2];
	unsigned long read_pos = 0;
	while(read_pos < m_MsgSize/4){
		uint32_t v0 = buffer[read_pos], v1 = buffer[read_pos + 1];
		uint32_t delta = 0x61C88647;
		uint32_t sum = 0xC6EF3720;
		
		for(long i = 0; i<32; i++) {
			v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum>>11 & 3]);
			sum += delta;
			v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
		}
		buffer[read_pos] = v0; buffer[read_pos + 1] = v1;
		read_pos = read_pos + 2;
	}
}

bool NetworkMessage::RSA_encrypt()
{
	int newPos = m_ReadPos - 128;
	if(newPos < 0){
		std::cout << "Warning: [NetworkMessage::RSA_decrypt()]. Not valid packet size" << std::endl;
		return false;
	}
	
	if(!m_RSA){
		std::cout << "Warning: [NetworkMessage::RSA_decrypt()]. m_RSA no set" << std::endl;
		return false;
	}
	
	if(!m_RSA->encrypt((char*)(m_MsgBuf + newPos), 128)){
		return false;
	}
	
	return true;
}

/**********************************************************************************

    CRYPTOSECURITY version 1.0. File Encryption Software
    Copyright (C) 2018  Maxim Shershavikov

    This file is part of CryptoSecurity v1.0.

    CryptoSecurity v1.0 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CryptoSecurity v1.0 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Email m.shershavikov@yandex.ru
    To read a copy of the GNU General Public License in a file COPYING.txt,
    to do this, click the AbautProgram button.

**********************************************************************************/

#include "HashMd5.h"

HASHMD5::HASHMD5(char *StringKey) : sizebyte(0), sizebit(0)
{
    Message = new char[64];
    DataHash = new DWORD[4];
    InitialValue = new DWORD[4];
    Data = reinterpret_cast<DWORD*>(Message);
    Md5Hash = reinterpret_cast<BYTE*>(DataHash);
    DataHash[0] = 0x67452301L;
    DataHash[1] = 0xefcdab89L;
    DataHash[2] = 0x98badcfeL;
    DataHash[3] = 0x10325476L;
    StreamProcessing(StringKey);
    *Md5Hash = MdHashProcessing();
}

HASHMD5::~HASHMD5()
{
    delete[] InitialValue;
    InitialValue = nullptr;
    Data = nullptr;
    delete[] Message;
    Message = nullptr;
    delete[] DataHash;
    DataHash = nullptr;
    Md5Hash = nullptr;
}

void HASHMD5::StreamProcessing(char *StringKey)
{
    sizebyte = static_cast<int>(strlen(StringKey));
    sizebit = sizebyte * 8;
    for (int i = 0; i < 64; i++)
    {
        if (i < sizebyte) Message[i] = StringKey[i];
        if (i == sizebyte && sizebyte < 56) Message[i] = static_cast<char>(0x80);
        if (i > sizebyte) Message[i] = 0;
    }
    if (sizebit <= 65535)
    {
        Data[14] = static_cast<DWORD>(sizebit);
    }
    if (sizebit > 65535)
    {
        ;
    }
}

void HASHMD5::RaundOperation(DWORD *ValOne, DWORD *ValTwo, DWORD *ValFhree, DWORD *ValFour, DWORD *Data, DWORD Kons, int i, int n)
{
    switch (n)
    {
        case 0:
            *ValOne += ((*ValTwo & *ValFhree) | (~*ValTwo & *ValFour)) + *Data + Kons;
            *ValOne = (*ValOne << i) | (*ValOne >> (32 - i));
            *ValOne += *ValTwo;
            break;
        case 1:
            *ValOne += ((*ValTwo & *ValFour) | (*ValFhree & ~*ValFour)) + *Data + Kons;
            *ValOne = (*ValOne << i) | (*ValOne >> (32 - i));
            *ValOne += *ValTwo;
            break;
        case 2:
            *ValOne += (*ValTwo ^ *ValFhree ^ *ValFour) + *Data + Kons;
            *ValOne = (*ValOne << i) | (*ValOne >> (32 - i));
            *ValOne += *ValTwo;
            break;
        case 3:
            *ValOne += (*ValFhree ^ (*ValTwo | ~*ValFour)) + *Data + Kons;
            *ValOne = (*ValOne << i) | (*ValOne >> (32 - i));
            *ValOne += *ValTwo;
            break;
    }
}

BYTE HASHMD5::MdHashProcessing()
{
    InitialValue[0] = DataHash[0];
    InitialValue[1] = DataHash[1];
    InitialValue[2] = DataHash[2];
    InitialValue[3] = DataHash[3];
    // Round 1
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[0],  0xd76aa478L, 7,  0);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[1],  0xe8c7b756L, 12, 0);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[2],  0x242070dbL, 17, 0);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[3],  0xc1bdceeeL, 22, 0);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[4],  0xf57c0fafL, 7,  0);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[5],  0x4787c62aL, 12, 0);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[6],  0xa8304613L, 17, 0);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[7],  0xfd469501L, 22, 0);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[8],  0x698098d8L, 7,  0);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[9],  0x8b44f7afL, 12, 0);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[10], 0xffff5bb1L, 17, 0);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[11], 0x895cd7beL, 22, 0);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[12], 0x6b901122L, 7,  0);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[13], 0xfd987193L, 12, 0);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[14], 0xa679438eL, 17, 0);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[15], 0x49b40821L, 22, 0);
    // Round 2
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[1],  0xf61e2562L, 5,  1);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[6],  0xc040b340L, 9,  1);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[11], 0x265e5a51L, 14, 1);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[0],  0xe9b6c7aaL, 20, 1);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[5],  0xd62f105dL, 5,  1);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[10], 0x02441453L, 9,  1);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[15], 0xd8a1e681L, 14, 1);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[4],  0xe7d3fbc8L, 20, 1);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[9],  0x21e1cde6L, 5,  1);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[14], 0xc33707d6L, 9,  1);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[3],  0xf4d50d87L, 14, 1);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[8],  0x455a14edL, 20, 1);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[13], 0xa9e3e905L, 5,  1);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[2],  0xfcefa3f8L, 9,  1);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[7],  0x676f02d9L, 14, 1);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[12], 0x8d2a4c8aL, 20, 1);
    // Round 3
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[5],  0xfffa3942L, 4,  2);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[8],  0x8771f681L, 11, 2);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[11], 0x6d9d6122L, 16, 2);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[14], 0xfde5380cL, 23, 2);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[1],  0xa4beea44L, 4,  2);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[4],  0x4bdecfa9L, 11, 2);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[7],  0xf6bb4b60L, 16, 2);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[10], 0xbebfbc70L, 23, 2);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[13], 0x289b7ec6L, 4,  2);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[0],  0xeaa127faL, 11, 2);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[3],  0xd4ef3085L, 16, 2);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[6],  0x04881d05L, 23, 2);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[9],  0xd9d4d039L, 4,  2);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[12], 0xe6db99e5L, 11, 2);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[15], 0x1fa27cf8L, 16, 2);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[2],  0xc4ac5665L, 23, 2);
    // Round 4
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[0],  0xf4292244L, 6,  3);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[7],  0x432aff97L, 10, 3);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[14], 0xab9423a7L, 15, 3);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[5],  0xfc93a039L, 21, 3);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[12], 0x655b59c3L, 6,  3);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[3],  0x8f0ccc92L, 10, 3);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[10], 0xffeff47dL, 15, 3);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[1],  0x85845dd1L, 21, 3);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[8],  0x6fa87e4fL, 6,  3);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[15], 0xfe2ce6e0L, 10, 3);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[6],  0xa3014314L, 15, 3);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[13], 0x4e0811a1L, 21, 3);
    RaundOperation(&DataHash[0], &DataHash[1], &DataHash[2], &DataHash[3], &Data[4],  0xf7537e82L, 6,  3);
    RaundOperation(&DataHash[3], &DataHash[0], &DataHash[1], &DataHash[2], &Data[11], 0xbd3af235L, 10, 3);
    RaundOperation(&DataHash[2], &DataHash[3], &DataHash[0], &DataHash[1], &Data[2],  0x2ad7d2bbL, 15, 3);
    RaundOperation(&DataHash[1], &DataHash[2], &DataHash[3], &DataHash[0], &Data[9],  0xeb86d391L, 21, 3);
    // Result
    DataHash[0] += InitialValue[0];
    DataHash[1] += InitialValue[1];
    DataHash[2] += InitialValue[2];
    DataHash[3] += InitialValue[3];
    return *Md5Hash;
}

/**********************************************************************************

    CRYPTOSECURITY version 1.1. File Encryption Software
    Copyright (C) 2019  Maxim Shershavikov

    This file is part of CryptoSecurity v1.1.

    CryptoSecurity v1.1 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CryptoSecurity v1.1 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Email m.shershavikov@yandex.ru
    To read a copy of the GNU General Public License in a file COPYING.txt,
    to do this, click the AbautProgram button.

**********************************************************************************/

#ifndef HASHMD5_H
#define HASHMD5_H

#include <cstring>

typedef unsigned char BYTE;
typedef unsigned long DWORD;

class HASHMD5
{
private:
    int   sizebyte;
    int   sizebit;
    char  *Message;
    DWORD *DataHash;
    DWORD *InitialValue;
    DWORD *Data;
    void  StreamProcessing(char *StringKey);
    void  RaundOperation(DWORD *ValOne, DWORD *ValTwo, DWORD *ValFhree, DWORD *ValFour, DWORD *Data, DWORD Kons, int i, int n);
    BYTE  MdHashProcessing();
public:
    BYTE  *Md5Hash;
    HASHMD5(char *StringKey);
    ~HASHMD5();
};

#endif // HASHMD5_H

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

#ifndef CRYPTON_H
#define CRYPTON_H

#define BIT 1
#define MASKAWORD 0x8000
#define MASKABIT 0x01

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef int BOOL;

class CRYPTOSECURITY
{
private:
    WORD Res;
    const WORD Modul;
    BYTE Result;
    BOOL *FByte;
    BOOL *SByte;
    WORD *WordPolinom;
    int j, i;
    int BitRes, BitMod;
protected:
    const BYTE ByteBoxCrypto[16][16];
    const BYTE ByteBoxDeCrypto[16][16];
    BYTE PolinomByte(BYTE *FerstByte, BYTE *SecondByte);
public:
    CRYPTOSECURITY();
    ~CRYPTOSECURITY();
};

#endif // CRYPTON_H

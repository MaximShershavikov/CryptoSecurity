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

#ifndef EXPANSEKEY_H
#define EXPANSEKEY_H

#include "CryptoSecurity.h"

class EXPANSEKEY : public CRYPTOSECURITY
{
private:
    int        x;
    int        y;
    int        block;
    BYTE       *Word;
    const BYTE ConstExKey[44];
    BYTE       KeyExpanse(BYTE *key);
    void       ByteOffset(int i, int a, int b, int c, int d);
    void       ByteSwapping(int s, int i);
public:
    BYTE       *ExKey;
    EXPANSEKEY(BYTE *key);
    ~EXPANSEKEY();
};

#endif // EXPANSEKEY_H

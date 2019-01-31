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

#include "ExpanseKey.h"

EXPANSEKEY::EXPANSEKEY(BYTE *key) : x(0), y(0), block(0),
ConstExKey{ 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
0x08, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0c,
0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x10, 0x00,
0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00 }
{
    Word = new BYTE[4];
    ExKey = new BYTE[176];
    *ExKey = KeyExpanse(key);
}

EXPANSEKEY::~EXPANSEKEY()
{
    delete[] Word;
    Word = nullptr;
    delete[] ExKey;
    ExKey = nullptr;
}

void EXPANSEKEY::ByteOffset(int i, int a, int b, int c, int d)
{
    Word[0] = ExKey[i - a];
    Word[1] = ExKey[i - b];
    Word[2] = ExKey[i - c];
    Word[3] = ExKey[i - d];
}

void EXPANSEKEY::ByteSwapping(int s)
{
    for (int i = 0; i < 4; i++)
    {
        y = Word[i] >> 4;
        x = Word[i] & 0x0F;
        Word[i] = ByteBoxCrypto[y][x];
    }
    Word[0] = Word[0] + ConstExKey[(s / 4) - 4];
}

BYTE EXPANSEKEY::KeyExpanse(BYTE *key)
{
    for (int i = 0; i < 176; i++)
    {
        if (i <= 15) ExKey[i] = key[i]; //RoundKey - ExKey
        if (block == 16)
        {
            ByteOffset(i, 3, 2, 1, 4);
            ByteSwapping(i);
            block = 0;
        }
        if (i >= 16 && block <= 3)
        {
            ExKey[i] = ExKey[i - 16] ^ Word[block]; //RoundKey - ExKey
        }
        if (i >= 16 && block > 3)
        {
            ExKey[i] = ExKey[i - 4] ^ ExKey[i - 16]; //RoundKey - ExKey
        }
        block++;
    }
    return *ExKey;
}


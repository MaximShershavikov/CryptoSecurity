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

#include "DeCrypt.h"

DECRYPT::DECRYPT() : ValueOwnDeCrypto(0), ValueTwoDeCrypto(0), WordDeCrypto(160),
ConstMixDeCrypto{ 0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d,
                  0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e }
{
    ColumsDataDeCrypto = new BYTE[4];
}

DECRYPT::~DECRYPT()
{
    delete[] ColumsDataDeCrypto;
    ColumsDataDeCrypto = nullptr;
}

void DECRYPT::AddExpanseKeyDeCrypto(BYTE *ExKey, BYTE *Data, int i)
{
    Data[i] ^= ExKey[WordDeCrypto + i];
    if (i < 15) AddExpanseKeyDeCrypto(ExKey, Data, ++i);
    else { WordDeCrypto -= 16; return; }
}

void DECRYPT::ColumnMixingDeCrypto(BYTE *Data, int i)
{
    if (ValueOwnDeCrypto == 0)
    {
        ColumsDataDeCrypto[0] = Data[0 + ValueTwoDeCrypto];
        ColumsDataDeCrypto[1] = Data[1 + ValueTwoDeCrypto];
        ColumsDataDeCrypto[2] = Data[2 + ValueTwoDeCrypto];
        ColumsDataDeCrypto[3] = Data[3 + ValueTwoDeCrypto];
    }
    Data[i] = (_PolinomByte(&ConstMixDeCrypto[ValueOwnDeCrypto * 4], &ColumsDataDeCrypto[0])) ^
        (_PolinomByte(&ConstMixDeCrypto[(ValueOwnDeCrypto * 4) + 1], &ColumsDataDeCrypto[1])) ^
        (_PolinomByte(&ConstMixDeCrypto[(ValueOwnDeCrypto * 4) + 2], &ColumsDataDeCrypto[2])) ^
        (_PolinomByte(&ConstMixDeCrypto[(ValueOwnDeCrypto * 4) + 3], &ColumsDataDeCrypto[3]));
    ValueOwnDeCrypto++;
    if (ValueOwnDeCrypto == 4) { ValueOwnDeCrypto = 0; ValueTwoDeCrypto += 4; }
    if (i < 15) ColumnMixingDeCrypto(Data, ++i);
    else return;
}

void DECRYPT::ByteOffsetDeCrypto(BYTE *Data)
{
    ValueOwnDeCrypto = Data[13];
    Data[13] = Data[9];
    Data[9] = Data[5];
    Data[5] = Data[1];
    Data[1] = static_cast<BYTE>(ValueOwnDeCrypto);
    ValueOwnDeCrypto = Data[10];
    Data[10] = Data[2];
    Data[2] = static_cast<BYTE>(ValueOwnDeCrypto);
    ValueOwnDeCrypto = Data[14];
    Data[14] = Data[6];
    Data[6] = static_cast<BYTE>(ValueOwnDeCrypto);
    ValueOwnDeCrypto = Data[3];
    Data[3] = Data[7];
    Data[7] = Data[11];
    Data[11] = Data[15];
    Data[15] = static_cast<BYTE>(ValueOwnDeCrypto);
}

void DECRYPT::ByteSwappingDeCrypto(BYTE *Data, int i)
{
    ValueOwnDeCrypto = Data[i] >> 4;
    ValueTwoDeCrypto = Data[i] & 0x0F;
    Data[i] = ByteBoxDeCrypto[ValueOwnDeCrypto][ValueTwoDeCrypto];
    if (i < 15) ByteSwappingDeCrypto(Data, ++i);
    else ValueOwnDeCrypto = 0; ValueTwoDeCrypto = 0; return;
}

void DECRYPT::EndByteXor(BYTE *ExKey, BYTE *Data, int i)
{
    Data[i] ^= ExKey[i];
    if (i < 15) EndByteXor(ExKey, Data, ++i);
    else return;
}

void DECRYPT::DeCryptRound(BYTE *ExKey, BYTE *Data)
{
    for (int i = 0; i < 10; i++)
    {
        if (i == 0)
        {
            AddExpanseKeyDeCrypto(ExKey, Data, 0);
            ByteOffsetDeCrypto(Data);
            ByteSwappingDeCrypto(Data, 0);
        }
        else
        {
            AddExpanseKeyDeCrypto(ExKey, Data, 0);
            ColumnMixingDeCrypto(Data, 0);
            ByteOffsetDeCrypto(Data);
            ByteSwappingDeCrypto(Data, 0);
        }
    }
    EndByteXor(ExKey, Data, 0);
    WordDeCrypto = 160;
}

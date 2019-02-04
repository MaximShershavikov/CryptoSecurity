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

#include "EnCrypt.h"

ENCRYPT::ENCRYPT() : ValueOwnCrypto(0), ValueTwoCrypto(0), WordCrypto(16),
ConstMixCrypto{ 0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01,
                0x01, 0x01, 0x02, 0x03, 0x03, 0x01, 0x01, 0x02 }
{
    ColumsDataCrypto = new BYTE[4];
}

ENCRYPT::~ENCRYPT()
{
    delete[] ColumsDataCrypto;
    ColumsDataCrypto = nullptr;
}

void ENCRYPT::ByteSwappingCrypto(BYTE *Data, int i)
{
    ValueOwnCrypto = Data[i] >> 4;
    ValueTwoCrypto = Data[i] & 0x0F;
    Data[i] = ByteBoxCrypto[ValueOwnCrypto][ValueTwoCrypto];
    if (i < 15) ByteSwappingCrypto(Data, ++i);
    else return;
}

void ENCRYPT::ByteOffsetCrypto(BYTE *Data)
{
    ValueOwnCrypto = Data[1];
    Data[1] = Data[5];
    Data[5] = Data[9];
    Data[9] = Data[13];
    Data[13] = static_cast<BYTE>(ValueOwnCrypto);
    ValueOwnCrypto = Data[2];
    Data[2] = Data[10];
    Data[10] = static_cast<BYTE>(ValueOwnCrypto);
    ValueOwnCrypto = Data[6];
    Data[6] = Data[14];
    Data[14] = static_cast<BYTE>(ValueOwnCrypto);
    ValueOwnCrypto = Data[3];
    Data[3] = Data[15];
    Data[15] = Data[11];
    Data[11] = Data[7];
    Data[7] = static_cast<BYTE>(ValueOwnCrypto);
    ValueOwnCrypto = 0;
    ValueTwoCrypto = 0;
}

void ENCRYPT::ColumnMixingCrypto(BYTE *Data, int i)
{
    if (ValueOwnCrypto == 0)
    {
        ColumsDataCrypto[0] = Data[0 + ValueTwoCrypto];
        ColumsDataCrypto[1] = Data[1 + ValueTwoCrypto];
        ColumsDataCrypto[2] = Data[2 + ValueTwoCrypto];
        ColumsDataCrypto[3] = Data[3 + ValueTwoCrypto];
    }
    Data[i] = (_PolinomByte(&ConstMixCrypto[ValueOwnCrypto * 4], &ColumsDataCrypto[0])) ^
        (_PolinomByte(&ConstMixCrypto[(ValueOwnCrypto * 4) + 1], &ColumsDataCrypto[1])) ^
        (_PolinomByte(&ConstMixCrypto[(ValueOwnCrypto * 4) + 2], &ColumsDataCrypto[2])) ^
        (_PolinomByte(&ConstMixCrypto[(ValueOwnCrypto * 4) + 3], &ColumsDataCrypto[3]));
    ValueOwnCrypto++;
    if (ValueOwnCrypto == 4) { ValueOwnCrypto = 0; ValueTwoCrypto += 4; }
    if (i < 15) ColumnMixingCrypto(Data, ++i);
    else return;
}

void ENCRYPT::AddExpanseKeyCrypto(BYTE *ExKey, BYTE *Data, int i)
{
    Data[i] ^= ExKey[WordCrypto + i];
    if (i < 15) AddExpanseKeyCrypto(ExKey, Data, ++i);
    else { WordCrypto += 16; return; }
}

void ENCRYPT::StartByteXor(BYTE *ExKey, BYTE *Data, int i)
{    
    Data[i] ^= ExKey[i];
    if (i < 15) StartByteXor(ExKey, Data, ++i);
    else return;
}

void ENCRYPT::CryptRound(BYTE *ExKey, BYTE *Data)
{
    StartByteXor(ExKey, Data, 0);
    for (int i = 0; i < 10; i++)
    {
        if (i < 9)
        {
            ByteSwappingCrypto(Data, 0);
            ByteOffsetCrypto(Data);
            ColumnMixingCrypto(Data, 0);
            AddExpanseKeyCrypto(ExKey, Data, 0);
        }
        else
        {
            ByteSwappingCrypto(Data, 0);
            ByteOffsetCrypto(Data);
            AddExpanseKeyCrypto(ExKey, Data, 0);
        }
    }
    WordCrypto = 16;
}

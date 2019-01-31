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

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "CryptoSecurity.h"

class ENCRYPT : CRYPTOSECURITY
{
private:
    int ValueOwnCrypto;
    int	ValueTwoCrypto;
    int WordCrypto;
    BYTE *ColumsDataCrypto;
    BYTE ConstMixCrypto[16];
    void ByteSwappingCrypto(BYTE *Data);
    void ByteOffsetCrypto(BYTE *Data);
    void ColumnMixingCrypto(BYTE *Data);
    void AddExpanseKeyCrypto(BYTE *ExKey, BYTE *Data, int i);
    void StartByteXor(BYTE *ExKey, BYTE *Data, int i);
public:
    ENCRYPT();
    ~ENCRYPT();
    void CryptRound(BYTE *ExKey, BYTE *Data);
};

#endif // ENCRYPT_H

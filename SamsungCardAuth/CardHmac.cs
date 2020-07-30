// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * SamsungCardAuth: Authenticates Samsung storage devices as genuine
 * Copyright (C) 2020  Yukai Li
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace SamsungCardAuth
{
    class CardHmac
    {
        int messageLength;
        byte[] messageBuffer;
        byte[] t1;
        byte[] t2;
        byte[] t3;
        HMACSHA256 hmac = new HMACSHA256();

        public CardHmac(int messageLength, byte[] t1, byte[] t2, byte[] t3)
        {
            this.messageLength = messageLength;
            messageBuffer = new byte[messageLength * 2];
            this.t1 = t1 ?? throw new ArgumentNullException(nameof(t1));
            this.t2 = t2 ?? throw new ArgumentNullException(nameof(t2));
            this.t3 = t3 ?? throw new ArgumentNullException(nameof(t3));
        }

        public byte[] Generate(ushort message, int round, bool actuallyProcess = true)
        {
            if (round > messageLength) throw new ArgumentOutOfRangeException(nameof(round));
            if (round != 0)
            {
                int offsetBase = (round - 1) * 2;
                messageBuffer[offsetBase] = (byte)message;
                messageBuffer[offsetBase + 1] = (byte)(message >> 8);
            }

            if (!actuallyProcess) return null;

            int x = message % messageLength;
            byte[] key = new byte[32];
            for (int i = 0; i < key.Length; ++i)
            {
                key[i] = (byte)(t1[(messageLength + i) % t1.Length] ^
                    t2[(x + i) % t2.Length] ^
                    t3[(messageLength + i + 5) % t3.Length]);
            }

            hmac.Key = key;
            return hmac.ComputeHash(messageBuffer);
        }
    }
}

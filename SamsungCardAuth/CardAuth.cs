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
using System.IO;

namespace SamsungCardAuth
{
    /// <summary>
    /// Provides logic for authentication of Samsung storage devices.
    /// </summary>
    public class CardAuth
    {
        const int ARG2_BASE = 0xc00000;
        const int ARG2_INTERVAL = 0x200000;
        const int CONTROLLER_TYPE_SECTOR = 0x544ee0;
        const int AUTHENTICATE_SECTOR = 0x800020;
        const int COMMAND_RANDOM_MASK = 0x1fff9f;
        const bool HMAC_PROCESS_EVERY_ROUND = false;
        static readonly int[] HEALTH_REPORT_MODE_KNOCK_SEQUENCE = {
            0x123420, 0x654340, 0x321560, 0x523480
        };
        static readonly byte[] HEALTH_REPORT_ENTERED_RESPONSE =
            Encoding.ASCII.GetBytes("ENTERED SAMSUNG CARD HEALTH REPORT MODE\0");

        #region Controller key tables

        static readonly byte[] CONTROLLER_80_TABLE_1 =
        {
            0x65, 0x0a, 0x73, 0x54, 0x76, 0x6a, 0x0a, 0xbb, 0x81, 0xc2, 0xc9, 0x2e, 0x92, 0x72, 0x2c, 0x85,
            0xa2, 0xbf, 0xe8, 0xa1, 0xa8, 0x1a, 0x66, 0x4b, 0xc2, 0x4b, 0x8b, 0x70, 0xc7, 0x6c, 0x51, 0xa3
        };

        static readonly byte[] CONTROLLER_80_TABLE_2 =
        {
            0xc6, 0xe0, 0x0b, 0xf3, 0xd5, 0xa7, 0x91, 0x47, 0x06, 0xca, 0x63, 0x51, 0x14, 0x29, 0x29, 0x67,
            0x27, 0xb7, 0x0a, 0x85, 0x2e, 0x1b, 0x21, 0x38, 0x4d, 0x2c, 0x6d, 0xfc, 0x53, 0x38, 0x0d, 0x13,
        };

        static readonly byte[] CONTROLLER_80_TABLE_3 =
        {
            0x39, 0x1c, 0x0c, 0xb3, 0x4e, 0xd8, 0xaa, 0x4a, 0x5b, 0x9c, 0xca, 0x4f, 0x68, 0x2e, 0x6f, 0xf3,
            0x74, 0x8f, 0x82, 0xee, 0x78, 0xa5, 0x63, 0x6f, 0x84, 0xc8, 0x78, 0x14, 0x8c, 0xc7, 0x02, 0x08,
        };

        static readonly byte[] CONTROLLER_176_TABLE_1 =
        {
            0x0a, 0x21, 0x39, 0x4d, 0xc6, 0xe0, 0x0b, 0xf3, 0xd5, 0xa7, 0x14, 0x29, 0x29, 0x67, 0x27, 0x85,
            0x2e, 0x1b, 0xb7, 0x2c, 0x6d, 0xfc, 0x53, 0x38, 0x0d, 0x13, 0x91, 0x47, 0x06, 0xca, 0x63, 0x51,
        };

        static readonly byte[] CONTROLLER_176_TABLE_2 =
        {
            0x4e, 0xb3, 0x50, 0x68, 0x2e, 0x6f, 0xf3, 0xd8, 0xaa, 0x4a, 0x5b, 0x63, 0x6f, 0x84, 0xc8, 0x78,
            0x14, 0x8c, 0xc7, 0x02, 0x08, 0x9c, 0xca, 0x39, 0x1c, 0x0c, 0x74, 0x8f, 0x82, 0xee, 0x78, 0xa5,
        };

        static readonly byte[] CONTROLLER_176_TABLE_3 =
        {
            0x76, 0x6a, 0x0b, 0xbb, 0x85, 0xa2, 0xbf, 0xe8, 0xa1, 0xa8, 0x1a, 0x8b, 0x70, 0xc7, 0x6c, 0x51,
            0xa3, 0x66, 0x4b, 0xc2, 0x4b, 0x81, 0xc2, 0xc9, 0x2e, 0x92, 0x65, 0x0a, 0x73, 0x54, 0x72, 0x2c,
        };

        static readonly byte[] CONTROLLER_179_TABLE_1 =
        {
            0x6f, 0xf3, 0x75, 0x8f, 0x5b, 0x9c, 0x39, 0x1c, 0x0c, 0xb3, 0x4e, 0xd8, 0xca, 0x4f, 0x68, 0x2e,
            0x6f, 0x84, 0xc8, 0x78, 0x14, 0x8c, 0xc7, 0x02, 0x08, 0x82, 0xee, 0x78, 0xa5, 0x63, 0xaa, 0x4a,
        };

        static readonly byte[] CONTROLLER_179_TABLE_2 =
        {
            0xc2, 0x4b, 0x8c, 0x70, 0xc7, 0x81, 0xc2, 0xc9, 0x2e, 0x92, 0x72, 0x2c, 0x85, 0xa2, 0xbf, 0xe8,
            0xa1, 0x6c, 0x51, 0xa3, 0x65, 0x0a, 0x73, 0x54, 0x76, 0x6a, 0x0a, 0xbb, 0xa8, 0x1a, 0x66, 0x4b,
        };

        static readonly byte[] CONTROLLER_179_TABLE_3 =
        {
            0x14, 0x29, 0x2a, 0x67, 0x27, 0x91, 0x47, 0x2c, 0x6d, 0xfc, 0x53, 0xb7, 0x0a, 0x85, 0x2e, 0x1b,
            0x21, 0xc6, 0xe0, 0x0b, 0xf3, 0xd5, 0xa7, 0x38, 0x0d, 0x13, 0x06, 0xca, 0x63, 0x51, 0x38, 0x4d,
        };

        #endregion

        IDisk disk;
        Random random = new Random();

        /// <summary>
        /// Instantiates a new instance of <see cref="CardAuth"/>.
        /// </summary>
        /// <param name="disk">The disk to authenticate.</param>
        /// <exception cref="ArgumentNullException"><paramref name="disk"/>is <c>null</c>.</exception>
        public CardAuth(IDisk disk)
        {
            this.disk = disk ?? throw new ArgumentNullException(nameof(disk));
        }

        /// <summary>
        /// Authenticate the device.
        /// </summary>
        /// <param name="lockDisk">Whether to try to obtain exclusive lock on the disk.</param>
        /// <returns>The result of the authentication attempt.</returns>
        public AuthenticationResult Authenticate(bool lockDisk)
        {
            if (!disk.IsOkForCheck()) return AuthenticationResult.UnsupportedDiskState;

            if (lockDisk)
            {
                if (!disk.Lock()) throw new IOException("Failed to lock disk.");
            }

            try
            {
                ResetSession(); // Exits authentication process in case previous attempt was cut short
                int tries = 5;
                while (tries > 0)
                {
                    if (EnterHealthReportMode()) break;
                    --tries;
                }
                if (tries == 0) return AuthenticationResult.FailedToEnterHealthReportMode;

                byte controllerType;
                try
                {
                    controllerType = GetControllerType(); // Note this is required prior to beginning authentication
                }
                catch
                {
                    return AuthenticationResult.FailedToGetControllerType;
                }

                return DoAuthenticate(controllerType) ? AuthenticationResult.Successful : AuthenticationResult.FailedToAuthenticate;
            }
            finally
            {
                if (lockDisk) disk.Unlock();
            }
        }

        void ResetSession()
        {
            ushort[] filler = GenerateRandomBuffer(20);
            for (int i = 0; i < filler.Length; ++i)
            {
                ReadSectorAt((ARG2_BASE + i * ARG2_INTERVAL) | (filler[i] << 5));
            }
        }

        bool EnterHealthReportMode()
        {
            byte[] response = null;
            foreach (int sector in HEALTH_REPORT_MODE_KNOCK_SEQUENCE)
            {
                response = ReadSectorAt(sector);
            }

            // Assume sector is longer than entered response
            for (int i = 0; i < HEALTH_REPORT_ENTERED_RESPONSE.Length; ++i)
            {
                if (HEALTH_REPORT_ENTERED_RESPONSE[i] != response[i])
                    return false;
            }
            return true;
        }

        byte GetControllerType()
        {
            byte[] buffer = ReadSectorAt(CONTROLLER_TYPE_SECTOR);
            return buffer[0];
        }

        bool DoAuthenticate(byte controllerType)
        {
            ushort[] message = GenerateRandomBuffer(16);
            CardHmac hmac = MakeHmac(controllerType, message.Length);
            if (hmac == null) return false;
            byte[] hmacResult = hmac.Generate(1, 0, false);
            // Initiate authentication
            ReadSectorAt(AUTHENTICATE_SECTOR | (random.Next() & COMMAND_RANDOM_MASK));

            int currSectorBase = ARG2_BASE;
            for (int i = 0; i < message.Length; ++i)
            {
                hmacResult = hmac.Generate(message[i], i + 1, HMAC_PROCESS_EVERY_ROUND || i == message.Length - 1);
                // Send round to card
                byte[] response = ReadSectorAt(currSectorBase | (message[i] << 5));
                currSectorBase += ARG2_INTERVAL;
                if (i == message.Length - 1)
                {
                    // Compare response
                    for (int j = 0; j < hmacResult.Length; ++j)
                    {
                        if (hmacResult[j] != response[j]) return false;
                    }
                }
            }

            return true;
        }

        static CardHmac MakeHmac(byte controllerType, int length)
        {
            byte[] t1;
            byte[] t2;
            byte[] t3;

            switch (controllerType)
            {
                case 80:
                    t1 = CONTROLLER_80_TABLE_1;
                    t2 = CONTROLLER_80_TABLE_2;
                    t3 = CONTROLLER_80_TABLE_3;
                    break;
                case 176:
                    t1 = CONTROLLER_176_TABLE_1;
                    t2 = CONTROLLER_176_TABLE_2;
                    t3 = CONTROLLER_176_TABLE_3;
                    break;
                case 179:
                    t1 = CONTROLLER_179_TABLE_1;
                    t2 = CONTROLLER_179_TABLE_2;
                    t3 = CONTROLLER_179_TABLE_3;
                    break;
                default:
                    //throw new ArgumentException("Unknown controller type.", nameof(controllerType));
                    return null;
            }

            return new CardHmac(length, t1, t2, t3);
        }

        byte[] ReadSectorAt(int sector)
        {
            disk.SeekSector(sector);
            return disk.ReadSectors(1);
        }

        ushort[] GenerateRandomBuffer(int count)
        {
            ushort[] nums = new ushort[count];
            for (int i = 0; i < nums.Length; ++i)
            {
                nums[i] = GenerateRandomNumber();
            }
            return nums;
        }

        ushort GenerateRandomNumber()
        {
            ushort num;
            do
            {
                num = (ushort)random.Next();
            }
            while (num == 0);
            return num;
        }
    }
}

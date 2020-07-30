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

namespace SamsungCardAuth
{
    /// <summary>
    /// Represents a disk device.
    /// </summary>
    public interface IDisk : IDisposable
    {
        /// <summary>
        /// Gets the name of the disk.
        /// </summary>
        string DisplayName { get; }

        /// <summary>
        /// Gains exclusive lock on the disk.
        /// </summary>
        /// <returns><c>true</c> if lock obtained, otherwise <c>false</c>.</returns>
        bool Lock();
        /// <summary>
        /// Releases exclusive lock on the disk.
        /// </summary>
        /// <returns><c>true</c> if lock was released, otherwise <c>false</c>.</returns>
        bool Unlock();
        /// <summary>
        /// Seek to a sector.
        /// </summary>
        /// <param name="sector">The sector number to seek to.</param>
        void SeekSector(int sector);
        /// <summary>
        /// Reads sectors.
        /// </summary>
        /// <param name="numSectors">The number of sectors to read.</param>
        /// <returns>The data that was read. It may be less than <paramref name="numSectors"/>.</returns>
        byte[] ReadSectors(int numSectors);
        /// <summary>
        /// Checks whether the disk state supports authentication.
        /// </summary>
        /// <returns><c>true</c> if the disk's state supports authentication, <c>false</c> otherwise.</returns>
        bool IsOkForCheck();
    }
}

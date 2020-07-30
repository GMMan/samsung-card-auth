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
using System.ComponentModel;
using WinFlashTool;
using Microsoft.WindowsAPICodePack.Shell;

namespace SamsungCardAuth.Windows
{
    /// <summary>
    /// Provides Windows-specific disk implementation.
    /// </summary>
    class WindowsDisk : IDisk
    {
        const int BYTES_PER_SECTOR = 512;

        DiskDevice volume;
        DiskDevice disk;
        bool disposed;
        string rootPath;

        /// <summary>
        /// Instantiates a new instance of <see cref="WindowsDisk"/>.
        /// </summary>
        /// <param name="name">The drive letter.</param>
        public WindowsDisk(string name)
        {
            rootPath = Path.GetPathRoot(Path.GetFullPath(name)).TrimEnd(Path.DirectorySeparatorChar);
            volume = new DiskDevice(@"\\.\" + rootPath, true);
            try
            {
                DiskDevice.STORAGE_DEVICE_NUMBER devNumber = volume.QueryDeviceNumber();
                disk = new DiskDevice(devNumber.PhysicalDrive, true);
            }
            catch
            {
                volume.Close();
                throw;
            }
        }

        /// <inheritdoc/>
        public string DisplayName => rootPath;

        /// <inheritdoc/>
        public void Dispose()
        {
            if (disk != null) disk.Close();
            if (volume != null) volume.Close();
            disposed = true;
        }

        void CheckDisposed()
        {
            if (disposed) throw new ObjectDisposedException(GetType().FullName);
        }

        /// <inheritdoc/>
        public bool IsOkForCheck()
        {
            if (disposed) return false;
            var bitlockerProp = ShellObject.FromParsingName(rootPath).Properties.GetProperty<int?>("System.Volume.BitLockerProtection");
            var propValue = bitlockerProp.Value;
            bool bitlockerEnabled = propValue.HasValue && (propValue.Value == 1 || propValue.Value == 3 || propValue.Value == 5);
            return !bitlockerEnabled;
        }

        /// <inheritdoc/>
        public bool Lock()
        {
            CheckDisposed();
            try
            {
                disk.Lock();
                return true;
            }
            catch (Win32Exception)
            {
                return false;
            }
        }

        /// <inheritdoc/>
        public byte[] ReadSectors(int numSectors)
        {
            CheckDisposed();
            return disk.Read(numSectors * BYTES_PER_SECTOR);
        }

        /// <inheritdoc/>
        public void SeekSector(int sector)
        {
            CheckDisposed();
            disk.SeekAbs((long)sector * BYTES_PER_SECTOR);
        }

        /// <inheritdoc/>
        public bool Unlock()
        {
            CheckDisposed();
            try
            {
                disk.Unlock();
                return true;
            }
            catch (Win32Exception)
            {
                return false;
            }
        }
    }
}

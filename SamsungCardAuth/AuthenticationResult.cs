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
    /// Represents the result of an authentication attempt.
    /// </summary>
    public enum AuthenticationResult
    {
        /// <summary>
        /// Authentication was successful and the disk is a genuine Samsung device.
        /// </summary>
        Successful,
        /// <summary>
        /// Device did not report entering Health Report Mode.
        /// </summary>
        FailedToEnterHealthReportMode,
        /// <summary>
        /// Could not read controller type from device.
        /// </summary>
        FailedToGetControllerType,
        /// <summary>
        /// Device authentication response did not match expected response.
        /// </summary>
        FailedToAuthenticate,
        /// <summary>
        /// Device cannot be authenticated in its current state.
        /// </summary>
        UnsupportedDiskState,
    }
}

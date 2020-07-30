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
using McMaster.Extensions.CommandLineUtils;
using SamsungCardAuth.Linux;
using SamsungCardAuth.Windows;
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace SamsungCardAuth
{
    class Program
    {
        static int Main(string[] args)
        {
            var app = new CommandLineApplication
            {
                Name = Path.GetFileName(Environment.GetCommandLineArgs()[0]),
                FullName = "Samsung Memory Card/USB Flash Drive Authenticator"
            };

            var listOpt = app.Option("-l|--list", "List available disks", CommandOptionType.NoValue);
            var diskPathArg = app.Argument("path", "Path of disk to authenticate");
            diskPathArg.Accepts().ExistingFileOrDirectory();

            app.OnExecute(() =>
            {
                IPlatformOperations platform;
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    platform = new WindowsPlatformOperations();
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    platform = new LinuxPlatformOperations();
                }
                else
                {
                    Console.Error.WriteLine("Current platform is not supported.");
                    return -3;
                }

                if (listOpt.HasValue())
                {
                    foreach (var vol in platform.GetVolumes())
                    {
                        Console.WriteLine(vol);
                    }
                }
                else if (diskPathArg.Value != null)
                {
                    if (!platform.GetVolumes().Contains(diskPathArg.Value))
                    {
                        Console.Error.WriteLine("Could not find specified device in available disks.");
                        return -4;
                    }

                    using (IDisk disk = platform.GetDisk(diskPathArg.Value))
                    {
                        CardAuth auth = new CardAuth(disk);
                        var result = auth.Authenticate(true);
                        Console.WriteLine("Authentication result: " + result);
                        if (result != AuthenticationResult.Successful) return 1;
                    }
                }
                else
                {
                    app.ShowHelp();
                }

                return 0;
            });

            app.VersionOptionFromAssemblyAttributes(System.Reflection.Assembly.GetExecutingAssembly());
            app.HelpOption();

            try
            {
                return app.Execute(args);
            }
            catch (CommandParsingException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return -1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed to authenticate: " + ex.Message);
                return -2;
            }
        }
    }
}

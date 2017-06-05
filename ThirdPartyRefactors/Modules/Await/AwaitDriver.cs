using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AwaitDriver
{
    public class AwaitDriver
    {
        /// <summary>
        /// Creates a new instance of the AwaitDriver class, which lets you perform
        /// expect-like functionality on Console applications.
        /// </summary>
        public AwaitDriver()
        {
            // Launch a new instance of PowerShell and steal its console input / output handles
            ProcessStartInfo startInfo = new ProcessStartInfo("C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoProfile");
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            driverHost = Process.Start(startInfo);

            System.Threading.Thread.Sleep(100);

            NativeMethods.FreeConsole();
            bool result = NativeMethods.AttachConsole(driverHost.Id);

            const UInt32 STD_INPUT_HANDLE = 0xFFFFFFF6;
            const UInt32 STD_OUTPUT_HANDLE = 0xFFFFFFF5;
            hInput = NativeMethods.GetStdHandle(STD_INPUT_HANDLE);
            hOutput = NativeMethods.GetStdHandle(STD_OUTPUT_HANDLE);
        }

        // Handles from the driver process
        Process driverHost = null;
        IntPtr hInput = IntPtr.Zero;
        IntPtr hOutput = IntPtr.Zero;

        // State to remember information between Read() calls so
        // that we don't have to scan the full buffer each time.
        int lastReadPosition = 0;
        List<string> lastRawContent = new List<string>();

        /// <summary>
        /// 
        /// Sends the specified input to the driver process. Does not
        /// include a newline at the end of the input.
        /// 
        /// Input can be basic characters, or can use the same set of metacharacters
        /// that the SendKeys() API supports, such as {ESC}.
        /// 
        /// http://msdn.microsoft.com/en-us/library/system.windows.forms.sendkeys.send(v=vs.110).aspx
        /// 
        /// While the syntax is the same as the SendKeys() API, the approach is not
        /// based on SendKeys() at all - to ensure that applications can be automated while
        /// you use your keyboard and mouse for other things.
        /// 
        /// </summary>
        /// <param name="text">The text to send</param>
        public void Send(string text)
        {
            List<NativeMethods.INPUT_RECORD> inputs = new List<NativeMethods.INPUT_RECORD>();

            foreach (string inputElement in SendKeysParser.Parse(text))
            {
                foreach (NativeMethods.INPUT_RECORD mappedInput in SendKeysParser.MapInput(inputElement))
                {
                    inputs.Add(mappedInput);
                }
            }

            uint eventsWritten = 0;
            NativeMethods.WriteConsoleInput(hInput, inputs.ToArray(), (uint)inputs.Count, out eventsWritten);
        }

        /// <summary>
        /// Sends the specified input to the driver process, including a trailing newline.
        /// </summary>
        /// <param name="text">The text to send</param>
        public void SendLine(string input)
        {
            Send(input + "{ENTER}");
        }

        /// <summary>
        /// Waits for the given string to be available as a command response, and
        /// returns the result of that reponse.
        /// 
        /// This method is stateful. Once output has been returned from an AwaitOutput()
        /// call, it will not be output again. Further AwaitOutput() calls will operate
        /// against output produced after preceeding AwaitOutput() calls complete.
        /// 
        /// </summary>
        /// <param name="expected">The string to search for in the command response.</param>
        public string AwaitOutput(string expected)
        {
            return AwaitOutput(expected, false);
        }

        /// <summary>
        /// Waits for the given string to be available as a command response, and
        /// returns the result of that reponse.
        /// 
        /// </summary>
        /// <param name="expected">The string to search for in the command response.</param>
        /// <param name="all">
        /// If 'All' is specified, this method acts against the entire content of the
        /// console buffer, and the output of this method is the entire content of the
        /// console buffer.
        /// </param>
        public string AwaitOutput(string expected, bool all)
        {
            // Save the internal buffer position state so that we can restore
            // it if the content doesn't match.
            int savedStartPosition = lastReadPosition;
            List<string> savedLastRawContent = new List<string>(lastRawContent);
            string output = null;

            // Should be able to replace this with a WinEventHook for console changes:
            // http://msdn.microsoft.com/en-us/library/windows/desktop/ms682102(v=vs.85).aspx
            while (true)
            {
                output = ReadOutput(all);

                if (output.Contains(expected))
                {
                    break;
                }
                else
                {
                    lastReadPosition = savedStartPosition;
                    lastRawContent = new List<string>(savedLastRawContent);
                }

                System.Threading.Thread.Sleep(10);
            }

            return output;
        }

        /// <summary>
        /// Closes the AwaitDriver class, which lets you perform
        /// expect-like functionality on Console applications.
        /// </summary>
        public void Close()
        {
            driverHost.Kill();
        }

        public string ReadOutput()
        {
            return ReadOutput(false);
        }

        // Can scrape 650 lines of output at 11ms per scrape.
        public string ReadOutput(bool all)
        {
            // Check the current console screen buffer dimensions, cursor coordinates / etc.
            NativeMethods.CONSOLE_SCREEN_BUFFER_INFO csbi;
            NativeMethods.GetConsoleScreenBufferInfo(hOutput, out csbi);

            StringBuilder output = new StringBuilder();

            // If the cursor has gone before where we last scanned, then the screen
            // has been cleared and we should reset our state.
            if (lastReadPosition > csbi.dwCursorPosition.Y + 1)
            {
                ResetLastScanInfo();
            }

            // If the cursor is at the end of the buffer, then we no longer have a
            // quick way to determine if new content has been written. To address this,
            // every ReadOutput() call retains the last 10 lines of output that it read.
            //
            // As we scan through the buffer, we fill the 'currentHeuristicContent' list
            // with the output lines we see. Once we have 10 matching lines of output, we
            // know we're at the end of the previous scan.
            //
            // Additionally, we only do this heuristic scan if they haven't specified the
            // 'All' flag.
            bool inHeuristicContentScan = false;
            List<string> currentHeuristicContent = new List<string>();

            if ((!all) && (lastReadPosition == csbi.dwSize.Y))
            {
                inHeuristicContentScan = true;
                lastReadPosition = 0;
            }

            // Figure out where to start and stop scanning
            int startReadPosition = lastReadPosition;
            int endReadPosition = csbi.dwCursorPosition.Y;

            if (all)
            {
                startReadPosition = 0;
                endReadPosition = csbi.dwSize.Y - 1;
            }

            // Go through each line in the buffer
            for (int row = startReadPosition; row <= endReadPosition; row++)
            {
                int width = csbi.dwMaximumWindowSize.X;
                StringBuilder lpCharacter = new StringBuilder(width - 1);

                // Read the current line from the buffer
                NativeMethods.COORD dwReadCoord;
                dwReadCoord.X = 0;
                dwReadCoord.Y = (short)row;

                uint lpNumberOfCharsRead = 0;
                NativeMethods.ReadConsoleOutputCharacter(hOutput, lpCharacter, (uint)width, dwReadCoord, out lpNumberOfCharsRead);

                // If we're in a heuristic scan, and the current line to the heuristic scan buffer
                if (inHeuristicContentScan)
                {
                    currentHeuristicContent.Add(lpCharacter.ToString());

                    // Ensure the two lists remain the same size
                    if (currentHeuristicContent.Count > lastRawContent.Count)
                    {
                        currentHeuristicContent.RemoveAt(0);
                    }

                    // If the heuristic scan buffer is the same size as the trailing buffer from the last ReadOutput()
                    // call, we can see if they match.
                    if (currentHeuristicContent.Count == lastRawContent.Count)
                    {
                        bool foundContentMatch = true;

                        // Only scan to the second-last line of the saved content buffer, as the last line
                        // is frequently different. For example, a prompt in the last scan, and now a prompt
                        // that includes the user's command.
                        for (int contentIndex = 0; contentIndex < currentHeuristicContent.Count - 1; contentIndex++)
                        {
                            if (lastRawContent[contentIndex] != currentHeuristicContent[contentIndex])
                            {
                                foundContentMatch = false;
                                break;
                            }
                        }

                        // All 10 lines matched
                        if (foundContentMatch)
                        {
                            inHeuristicContentScan = false;
                            continue;
                        }
                    }
                }

                // If we're not just scanning through the buffer heuristically, then capture the content.
                if (!inHeuristicContentScan)
                {
                    lastRawContent.Add(lpCharacter.ToString());

                    if (lastRawContent.Count > 10)
                    {
                        lastRawContent.RemoveAt(0);
                    }

                    output.AppendLine(lpCharacter.ToString().Substring(0, width).TrimEnd());
                }
            }

            // Update our state to remember where to start scanning the buffer next.
            lastReadPosition = endReadPosition + 1;

            // If we were at the end of the buffer and made it all the way here without matching,
            // then our heuristics (i.e.: detecting clearing the screen) got broken.
            // This can happen with repetitive commands when the buffer is full, such as:

            // Get-Date
            // cls
            // Get-Date

            // Reset them.
            if (inHeuristicContentScan)
            {
                ResetLastScanInfo();
                return ReadOutput(all);
            }
            else
            {
                // We got content - return it.
                return output.ToString().TrimEnd();
            }
        }

        private void ResetLastScanInfo()
        {
            lastReadPosition = 0;
            lastRawContent.Clear();
        }
    }

    class SendKeysParser
    {
        public static List<string> Parse(string input)
        {
            List<string> output = new List<string>();

            bool scanningKeyName = false;
            StringBuilder keyNameBuffer = new StringBuilder();

            // Iterate through the string
            for (int index = 0; index < input.Length; index++)
            {
                // Save the current item
                char currentChar = input[index];

                // We may have the start of a command
                if (currentChar == '{')
                {
                    if (scanningKeyName)
                    {
                        throw new Exception("The character '{' is not a valid in a key name. " +
                            "To include the '{' character in your text, escape it with another: {{.");
                    }

                    // If it's escaped, then add it to output.
                    if ((index < (input.Length - 1)) &&
                        (input[index + 1] == '{'))
                    {
                        output.Add(currentChar.ToString());
                        index++;
                    }
                    else
                    {
                        // Otherwise, we found the start of a key name.
                        scanningKeyName = true;
                    }
                }
                else if (currentChar == '}')
                {
                    // We may have the end of a key name

                    // If it's escaped, then add it to output.
                    if ((index < (input.Length - 1)) &&
                        (input[index + 1] == '}'))
                    {
                        // But not if we're scanning a key name
                        if (scanningKeyName)
                        {
                            throw new Exception("The character '}' is not a valid in a key name. " +
                                "To include the '}' character in your text, escape it with another: }}.");
                        }

                        output.Add(currentChar.ToString());
                        index++;
                    }
                    else
                    {
                        // Not escaped

                        // If we're scanning a key name, record it.
                        if (scanningKeyName)
                        {
                            string keyName = keyNameBuffer.ToString();
                            if (String.IsNullOrEmpty(keyName))
                            {
                                throw new Exception("Key names may not be empty.");
                            }

                            output.Add(keyNameBuffer.ToString());
                            scanningKeyName = false;
                        }
                        else
                        {
                            throw new Exception("The character '}' is not a valid by itself. " +
                                "To include the '}' character in your text, escape it with another: }}.");
                        }
                    }
                }
                else
                {
                    // Just a letter
                    if (scanningKeyName)
                    {
                        keyNameBuffer.Append(currentChar);
                    }
                    else
                    {
                        output.Add(currentChar.ToString());
                    }
                }
            }

            // We got to the end of the string.
            if (scanningKeyName)
            {
                throw new Exception("The character '{' (representing the start of a key name) did not have a matching '}' " +
                    "character. To include the '{' character in your text, escape it with another: {{.");
            }

            return output;
        }

        internal static List<NativeMethods.INPUT_RECORD> MapInput(string inputElement)
        {
            List<NativeMethods.INPUT_RECORD> inputs = new List<NativeMethods.INPUT_RECORD>();

            NativeMethods.INPUT_RECORD input = new NativeMethods.INPUT_RECORD();
            input.EventType = 0x0001;

            NativeMethods.KEY_EVENT_RECORD keypress = new NativeMethods.KEY_EVENT_RECORD();
            keypress.dwControlKeyState = 0;
            keypress.wRepeatCount = 1;

            // Just a regular character
            if (inputElement.Length == 1)
            {
                keypress.UnicodeChar = inputElement[0];
            }
            else
            {
                switch (inputElement.ToUpperInvariant())
                {
                    case "BACKSPACE":
                    case "BS":
                    case "BKSP":
                        keypress = GetKeyPressForSimpleKey(keypress, 0x08);
                        break;

                    case "BREAK":
                        keypress = GetKeyPressForSimpleKey(keypress, 0x03);
                        keypress.dwControlKeyState = (uint) NativeMethods.ControlKeyStates.LEFT_CTRL_PRESSED;
                        keypress.UnicodeChar = (char) 0;
                        break;

                    case "ENTER":
                        keypress = GetKeyPressForSimpleKey(keypress, 0x0D);
                        break;

                    case "ESC":
                        keypress = GetKeyPressForSimpleKey(keypress, 0x1B);
                        break;
                }
            }

            keypress.bKeyDown = true;
            input.KeyEvent = keypress;
            inputs.Add(input);

            keypress.bKeyDown = false;
            keypress.dwControlKeyState = 0;
            input.KeyEvent = keypress;
            inputs.Add(input);

            return inputs;
        }

        private static NativeMethods.KEY_EVENT_RECORD GetKeyPressForSimpleKey(NativeMethods.KEY_EVENT_RECORD keypress, uint uCode)
        {
            keypress.UnicodeChar = (char)uCode;
            keypress.wVirtualKeyCode = (ushort)uCode;
            keypress.wVirtualScanCode = (ushort)NativeMethods.MapVirtualKey(uCode, MAPVK_VK_TO_VSC);
            return keypress;
        }

        const ushort MAPVK_VK_TO_VSC = 0x00;
    }

    class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool AttachConsole(int pid);

        [DllImport("kernel32.dll")]
        internal static extern bool FreeConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteConsoleInput(IntPtr hConsoleInput, INPUT_RECORD[] lpBuffer, uint nLength, out uint lpNumberOfEventsWritten);

        [DllImport("user32.dll")]
        internal static extern uint MapVirtualKey(uint uCode, uint uMapType);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetStdHandle(uint nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool FlushConsoleInputBuffer(IntPtr hConsoleInput);

        [DllImport("Kernel32")]
        internal static extern bool ReadConsoleOutputCharacter(IntPtr hConsoleOutput, StringBuilder lpCharacter, uint nLength, COORD dwReadCoord, out uint lpNumberOfCharsRead);

        [DllImport("kernel32.dll")]
        internal static extern bool GetConsoleScreenBufferInfo(IntPtr hConsoleOutput, out CONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo);

        [StructLayout(LayoutKind.Sequential)]
        internal struct COORD
        {
            internal short X;
            internal short Y;
        }

        internal struct SMALL_RECT
        {
            internal short Left;
            internal short Top;
            internal short Right;
            internal short Bottom;
        }

        internal struct CONSOLE_SCREEN_BUFFER_INFO
        {
            internal COORD dwSize;
            internal COORD dwCursorPosition;
            internal short wAttributes;
            internal SMALL_RECT srWindow;
            internal COORD dwMaximumWindowSize;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct INPUT_RECORD
        {
            [FieldOffset(0)]
            internal ushort EventType;
            [FieldOffset(4)]
            internal KEY_EVENT_RECORD KeyEvent;
        };

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        internal struct KEY_EVENT_RECORD
        {
            [FieldOffset(0), MarshalAs(UnmanagedType.Bool)]
            internal bool bKeyDown;
            [FieldOffset(4), MarshalAs(UnmanagedType.U2)]
            internal ushort wRepeatCount;
            [FieldOffset(6), MarshalAs(UnmanagedType.U2)]
            internal ushort wVirtualKeyCode;
            [FieldOffset(8), MarshalAs(UnmanagedType.U2)]
            internal ushort wVirtualScanCode;
            [FieldOffset(10)]
            internal char UnicodeChar;
            [FieldOffset(12), MarshalAs(UnmanagedType.U4)]
            internal uint dwControlKeyState;
        }

        internal enum ControlKeyStates
        {
            RIGHT_ALT_PRESSED = 0x1,
            LEFT_ALT_PRESSED = 0x2,
            RIGHT_CTRL_PRESSED = 0x4,
            LEFT_CTRL_PRESSED = 0x8,
            SHIFT_PRESSED = 0x10,
            NUMLOCK_ON = 0x20,
            SCROLLLOCK_ON = 0x40,
            CAPSLOCK_ON = 0x80,
            ENHANCED_KEY = 0x100
        }
    }
}
# RDP Credentials Decrypter

A C++ tool designed to automate the extraction and decryption of Windows Remote Desktop Protocol (RDP) credentials stored on a local machine.

## Description

This utility streamlines the process of recovering RDP credentials by leveraging a bundled Mimikatz binary. It automatically scans the system for credential files located in the users' `AppData` directories, extracts DPAPI master keys, and invokes Mimikatz to decrypt the credentials.

The tool is designed to operate discreetly by:
- Dropping the Mimikatz binary into a temporary directory with a random filename.
- Executing commands via hidden pipes to capture output without showing console windows.
- Cleaning up the dropped binary upon completion.

## Features

- **Automatic Discovery**: Scans `C:\Users\*\AppData\Local\Microsoft\Credentials` for stored RDP credentials.
- **DPAPI Integration**: Automatically retrieves the necessary DPAPI master keys from memory using `sekurlsa::dpapi`.
- **Automated Decryption**: Matches credential files to their corresponding master keys and decrypts them to reveal usernames and passwords.
- **Stealth Execution**: Uses hidden process creation and temporary file randomization.

## Installation & Requirements

### Prerequisites
- **Operating System**: Windows (Requires Administrative privileges to access other users' folders and run `privilege::debug`).
- **Compiler**: A C++ compiler supporting C++11 or later (e.g., Visual Studio/MSVC).
- **Dependencies**: Windows API headers.

### Building
1. Clone the repository.
2. Compile `RDP-credentials-decrypter.cpp` and `mimikatzBin.c` into a single executable.
3. Ensure the binary is linked against the necessary Windows libraries.

## Usage

1. Run the compiled executable as an **Administrator**.
2. The program will perform the following steps:
   - Drop the internal Mimikatz binary to the `%TEMP%` folder.
   - Enumerate all user credential files.
   - Extract DPAPI keys.
   - Decrypt and print the usernames and passwords to the console.
3. The temporary Mimikatz binary will be deleted automatically once the process is finished.

## Disclaimer

This tool is intended for authorized security auditing and educational purposes only. Using this software to gain unauthorized access to systems is illegal. The author is not responsible for any misuse of this tool.

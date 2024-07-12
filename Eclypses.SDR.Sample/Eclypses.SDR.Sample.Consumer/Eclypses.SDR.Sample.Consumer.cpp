/*******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) Eclypses, Inc.
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *******************************************************************************/

#include <iostream>
#include <string>
#include <cstring>
#include <algorithm>

#include "MteBase.h"
#include "MteSdr.h"
#include "Consumer.h"
#include "MteSdrDisconnected.h"

#if defined(_MSC_VER)
#  pragma warning(disable:4996)
#endif

std::string getItemFromSettings(std::string key) {
	std::ifstream file("./settings.txt");
	std::string s;
	while (std::getline(file, s)) {
		std::size_t found = s.find(key);
		if (found != std::string::npos) {
			std::size_t eq = s.find('=');
			if (eq != std::string::npos) {
				return s.substr(eq + 1);
			}
		}
	}
	return "";
}

int main()
{
	std::cout << "---------------------------" << std::endl;
	std::cout << "Eclypses MteSdr Demo Consumer" << std::endl;

	//
	// Initialize MTE license. 
	//
	std::string company = getItemFromSettings("LicensedCompany");
	std::string license = getItemFromSettings("LicenseKey");
	if (!MteBase::initLicense(company.c_str(), license.c_str()))
	{
		std::cerr << "License init error ("
			<< MteBase::getStatusName(mte_status_license_error)
			<< "): "
			<< MteBase::getStatusDescription(mte_status_license_error)
			<< std::endl;
		return mte_status_license_error;
	}
	std::cout << "Version of MTE Library: " << MteBase::getVersion() << " - licensed to: " << company << std::endl;
	std::cout << "---------------------------" << std::endl;
	//
	// Get a file name to reveal.
	//
	std::cout << "Enter a file name that you wish to reveal.  Once it is processed, it will be saved in the same folder with a '.clear' extension." << std::endl;
	std::string filename;
	std::getline(std::cin, filename);
	//
	// Read a protected file into memory
	//
	size_t fileSize;
	const uint8_t* protectedData = readFile(filename, fileSize);
	std::cout << "Protected file succesfully read - " << fileSize << " bytes" << std::endl;
	//
	// Initialize the Eclypses SDR with a security string that matches both the Concealer and the Revealer;
	//
	MteSdrDisconnected sdr = MteSdrDisconnected((mte_sdr_random)MteRandom::getBytes);
	sdr.initSdr("SecurityString");
	//
	// Reveal the data using Eclypses MTE
	//
	size_t clearLen;
	const uint8_t* revealed = sdr.Reveal(protectedData, fileSize, clearLen);
	//
	// Write the revealed file
	//
	std::string revealedFileName = filename + ".clear";
	writeFile(revealedFileName, revealed, clearLen);
	std::cout << "Original file (" << revealedFileName << ") successfully written - " << clearLen << " bytes" << std::endl;
}
const uint8_t* readFile(const std::string& filePath, size_t& valueBytes) {
	std::cout << "Reading original protected file - " << filePath << std::endl;
	const uint8_t* value = nullptr;
	std::ifstream fs(filePath.c_str(),
		std::ios::in | std::ios::binary);
	if (!fs.is_open())
	{
		value = nullptr;
		valueBytes = 0;
		return nullptr;
	}
	fs.seekg(0, std::ios::end);
	valueBytes = fs.tellg();
	value = new uint8_t[valueBytes];
	if (value == nullptr)
	{
		valueBytes = 0;
		fs.close();
		return nullptr;
	}
	fs.seekg(0, std::ios::beg);
	fs.read((char*)(value), valueBytes);
	if (fs.bad() || (size_t)fs.gcount() != valueBytes)
	{
		value = nullptr;
		valueBytes = 0;
		fs.close();
		return nullptr;
	}
	fs.close();
	return value;
}

void writeFile(const std::string fileName, const uint8_t* data, size_t dataLen) {
	std::ofstream fs(fileName, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!fs.is_open())
		return;
	fs.write((char*)data, dataLen);
	if (fs.bad())
		return;
	fs.close();
	return;
}
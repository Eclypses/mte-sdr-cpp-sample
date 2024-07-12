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
#include  "MteSdr.h"

MteSdr::MteSdr(mte_sdr_random rnd_cb) :
	myEncoder(NULL), myDecoder(NULL),
	myEncBuff(NULL), myEncBuffBytes(0),
	myDecBuff(NULL), myDecBuffBytes(0)
{
	myRandomCallback = rnd_cb;
}

MteSdr::~MteSdr()
{
	// Delete the buffers.
	delete[] myEncoder;
	delete[] myDecoder;
	delete[] myEncBuff;
	delete[] myDecBuff;
}

void MteSdr::initSdr(const std::string& location, const uint8_t* password, size_t passwordBytes)
{
	// Save the SDR path.
	mySdrLocation = location;

	// Check if password has been set with initSdr.
	if (password == nullptr || passwordBytes == 0)
	{
		myPasswordBytes = 0;
		myPassword = nullptr;
	}
	else
	{
		// Set the password.
		myPasswordBytes = passwordBytes;
		myPassword = new uint8_t[passwordBytes];
		memcpy(myPassword, password, myPasswordBytes);
	}

	// If the SDR location does not exist, create it.
	if (!locationExists(mySdrLocation))
	{
		setupLocation(mySdrLocation);
	}

	// Get the encoder size.
	size_t encBytes = mte_sdr_enc_state_bytes();

	// Allocate the encoder.
	myEncoder = new MTE_HANDLE[encBytes];

	// Get the decoder size.
	size_t decBytes = mte_sdr_dec_state_bytes();

	// Allocate the decoder.
	myDecoder = new MTE_HANDLE[decBytes];
}

void MteSdr::initSdr(const std::string& location, const std::string& password)
{
	const uint8_t* passPointer = reinterpret_cast<const uint8_t*>(password.data());
	initSdr(location, passPointer, password.length());
}

const uint8_t* MteSdr::readData(const std::string& key, size_t& decryptedBytes)
{
	mte_status status;

	uint8_t* encrypted = nullptr;
	size_t encryptedBytes;
	// Get the encrypted data.
	// First check if encrypted data is in memory.
	auto encryptedMem = memRecords.find(key);
	if (encryptedMem != memRecords.end())
	{
		encrypted = encryptedMem->second.second;
		encryptedBytes = encryptedMem->second.first;
	}
	else
	{
		// Attempt to get the record from the file system.
		encrypted = readRecord(mySdrLocation, key, encryptedBytes);
	}

	// Decode the encrypted data.
	const uint8_t* decrypted = decrypt(encrypted, encryptedBytes, decryptedBytes, status);
	if (status != mte_status_success)
	{
		throw std::runtime_error(std::string("Error decrypting data (") + MteBase::getStatusName(status) +
			"): " + MteBase::getStatusDescription(status));
	}

	return decrypted;
}

const std::string MteSdr::readString(const std::string& key)
{
	size_t decryptedBytes;
	const char* decrypted = reinterpret_cast<const char*>(readData(key, decryptedBytes));
	std::string decryptedString(decrypted);
	return decryptedString;
}

void MteSdr::write(const std::string& key, const uint8_t* value, size_t valueBytes, bool toMemory)
{
	// Encrypt the data.
	mte_status status;
	size_t encryptedBytes;
	const uint8_t* encrypted = static_cast<const uint8_t*>(encrypt(value, valueBytes, encryptedBytes, status));

	if (status != mte_status_success)
	{
		throw std::runtime_error(std::string("Error encrypting data (") + MteBase::getStatusName(status) +
			"): " + MteBase::getStatusDescription(status));
	}

	if (toMemory)
	{
		// If saving to memory, add it to the memory map.
		std::pair<size_t, uint8_t*> byteArray;
		byteArray.first = encryptedBytes;
		byteArray.second = new uint8_t[encryptedBytes];
		memcpy(byteArray.second, encrypted, encryptedBytes);

		removeRecord(mySdrLocation, key);
		memRecords.emplace(key, byteArray);

	}
	else
	{
		// Otherwise write it to the file.
		writeRecord(mySdrLocation, key, encrypted, encryptedBytes);
	}

}

void MteSdr::write(const std::string& key, const std::string& value, bool toMemory)
{
	const uint8_t* valuePointer = reinterpret_cast<const uint8_t*>(value.data());
	write(key, valuePointer, value.length(), toMemory);
}

void MteSdr::write(const std::string& key, const uint8_t* value, size_t valueBytes)
{
	write(key, value, valueBytes, false);
}

void MteSdr::write(const std::string& key, const std::string& value)
{
	const uint8_t* valuePointer = reinterpret_cast<const uint8_t*>(value.data());
	write(key, valuePointer, value.length(), false);
}

void MteSdr::remove(const std::string& key)
{
	// Remove from memory if it exists there.
	auto item = memRecords.find(key);
	if (item != memRecords.end())
	{
		memRecords.erase(item);
	}
	else
	{
		// Remove from the SDR if it exists there.
		removeRecord(mySdrLocation, key);
	}
}

void MteSdr::removeSdr()
{
	// Clear the memory storage.
	memRecords.clear();

	// If the SDR directory exists, remove it.
	if (locationExists(mySdrLocation))
	{
		// Remove each file.
		std::list<std::string> records = listRecords(mySdrLocation);
		for (std::list<std::string>::iterator record = records.begin();
			record != records.end(); ++record)
		{
			removeRecord(mySdrLocation, record->data());
		}

		// Remove the SDR directory.
		removeLocation(mySdrLocation);
	}
}

std::string MteSdr::mkFilePath(const std::string& path, const std::string& file)
{
	std::string filepath = path;
	if (filepath.back() != Separator)
		filepath += Separator;
	filepath.append(file);
	return filepath;
}

bool MteSdr::locationExists(const std::string& location)
{
	// Check if location string is empty.
	if (isNullOrWhitespace(location))
	{
		return false;
	}

#if defined(WIN32) || defined(_WIN32)
	DWORD attr = GetFileAttributesA(location.c_str());
	if (attr == INVALID_FILE_ATTRIBUTES)
	{
		// Item does not exist.
		return false;
	}
	else
	{
		// Determine if directory or something else.
		return (attr & FILE_ATTRIBUTE_DIRECTORY) ? true : false;
	}
#else
	struct stat info;

	if (stat(location.c_str(), &info) != 0)
		return false;
	else if (info.st_mode & S_IFDIR)
		return true;
	else
		return false;
#endif
}

bool MteSdr::recordExists(const std::string& location,
	const std::string& key)
{
	struct stat info;
	if (stat(mkFilePath(location, key).c_str(), &info) != 0)
		return false;
	else if (info.st_mode & S_IFREG)
		return true;
	else
		return false;
}

#if !defined(WIN32) && !defined(_WIN32)
static int dummy_filter(const struct dirent* name)
{
	return 1;
}
#endif

std::list<std::string> MteSdr::listRecords(const std::string& location)
{
	std::list<std::string> results;
	results.clear();
#if defined(WIN32) || defined(_WIN32)
	std::string filePath = mkFilePath(location, "*");
	// Find the first file in the directory.
	WIN32_FIND_DATAA ffd;
	HANDLE hFind = FindFirstFileA(filePath.c_str(), &ffd);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		// Get all the file names in the directory.
		do
		{
			if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				results.push_back(ffd.cFileName);
		} while (FindNextFileA(hFind, &ffd) != 0);
	}
	FindClose(hFind);
#else
	struct dirent** names = nullptr;
	int c = scandir(location.c_str(), &names, dummy_filter, alphasort);
	while (c--)
	{
		if (names[c]->d_type == DT_REG)
			results.push_back(names[c]->d_name);
		free(names[c]);
	}
	if (names != nullptr)
		free(names);
#endif
	return results;
}

void MteSdr::setupLocation(const std::string& location)
{
	// Check if location string is empty.
	if (!isNullOrWhitespace(location))
	{
		std::string myPath = location;
		if (myPath.back() == Separator)
		{
			myPath.pop_back();
		}
		mkAllDir(myPath);
	}
}

uint8_t* MteSdr::readRecord(const std::string& location, const std::string& key,
	size_t& valueBytes)
{
	uint8_t* value = nullptr;
	std::ifstream fs(mkFilePath(location, key).c_str(),
		std::ios::in | std::ios::binary);
	if (!fs.is_open())
	{
		value = nullptr;
		valueBytes = 0;
		return value;
	}
	fs.seekg(0, std::ios::end);
	valueBytes = fs.tellg();
	value = new uint8_t[valueBytes];
	if (value == nullptr)
	{
		valueBytes = 0;
		fs.close();
		return value;
	}
	fs.seekg(0, std::ios::beg);
	fs.read((char*)(value), valueBytes);
	if (fs.bad() || (size_t)fs.gcount() != valueBytes)
	{
		delete value;
		value = nullptr;
		valueBytes = 0;
		fs.close();
		return value;
	}
	fs.close();
	return value;
}

void MteSdr::writeRecord(const std::string& location, const std::string& key,
	const uint8_t* value, size_t valueBytes)
{
	std::ofstream fs(mkFilePath(location, key).c_str(),
		std::ios::out | std::ios::binary | std::ios::trunc);
	if (!fs.is_open())
		return;
	fs.write((char*)value, valueBytes);
	if (fs.bad())
		return;
	fs.close();
	return;
}

void MteSdr::removeLocation(const std::string& location)
{

#if defined(WIN32) || defined(_WIN32)
	_rmdir(location.c_str());
#else
	rmdir(location.c_str());
#endif
}

void MteSdr::removeRecord(const std::string& location, const std::string& key)
{
	std::string filepath = mkFilePath(location, key);
	struct stat info;
	if (stat(filepath.c_str(), &info) != 0)
	{
		printf("%d\n", errno);
		return;
	}
	else if (info.st_mode & S_IFREG)
	{
		::remove(filepath.c_str());
	}
}

const uint8_t* MteSdr::encrypt(const uint8_t* data, size_t dataBytes, size_t& encryptedBytes, mte_status& status)
{
	// Get the encrypted buffer requirement and reallocate if necessary.
	size_t buffBytes = mte_sdr_enc_buff_bytes(myEncoder, dataBytes);
	if (buffBytes > myEncBuffBytes)
	{
		delete[] myEncBuff;
		myEncBuff = new uint8_t[buffBytes];
		myEncBuffBytes = buffBytes;
	}

	// This variable will go in to the encrypt function as the size of the data
	// going in.
	size_t bytes = dataBytes;

	// Encrypt the data.
	status = mte_sdr_encrypt(myEncoder, data, &bytes, myEncBuff, myPassword, myPasswordBytes, MteSdrRandomCallback, this);

	// After the call, bytes will be the size of the encrypted data.
	encryptedBytes = bytes;

	// Return the encrypted data.
	return myEncBuff;
}

const uint8_t* MteSdr::decrypt(const uint8_t* encryptedData, size_t encryptedBytes, size_t& decryptedBytes, mte_status& status)
{
	// Get the decrypted buffer requirement and reallocate if necessary.
	size_t buffBytes = mte_sdr_dec_buff_bytes(myDecoder, encryptedBytes);
	if (buffBytes > myDecBuffBytes)
	{
		delete[] myDecBuff;
		myDecBuff = new uint8_t[buffBytes];
		myDecBuffBytes = buffBytes;
	}

	// This variable will go in to the decrypt function as the size of the
	// encrypted data going in.
	size_t bytes = encryptedBytes;

	// Decrypt the encrypted data.
	uint8_t dOff = 0;
	status = mte_sdr_decrypt(myDecoder, encryptedData, &bytes, myDecBuff, &dOff, myPassword, myPasswordBytes);

	// After the call, bytes will be the size of the decrypted data.
	decryptedBytes = bytes;

	// Return the decrypted version.
	return myDecBuff + dOff;
}

int MteSdr::mkAllDir(const std::string& path) const
{
	// The startPath will start as the path coming in, then each sub directory
	// in the name will get added to the finishPath.
	std::string startPath = path;
	std::string finishPath;

	// Loop through the passed in path until all subdirectories have been
	// checked and created as needed.
	bool finished = false;
	while (!finished)
	{
		// Find position of separator character.
		size_t sepPos = startPath.find(Separator);

		if (sepPos == std::string::npos)
		{
			finished = true;
			finishPath.append(startPath);
		}
		else
		{
			finishPath.append(startPath.substr(0, sepPos + 1));
		}

		// Check if directory already exists.
#if defined(WIN32) || defined(_WIN32)
		struct _stat stats;
		int rc = _stat(finishPath.c_str(), &stats);
		// If rc == 0, it is a directory or file that exists.
		if (rc != 0)
		{
			// Attempt to create the directory.
			rc = _mkdir(finishPath.c_str());
			if (rc != 0)
			{
				return rc;
			}
		}
#else
		struct stat stats;
		int rc = stat(finishPath.c_str(), &stats);

		// If rc == 0, it is a directory or file that exists.
		if (rc != 0)
		{
			// Determine if it is a directory.
			if (stats.st_mode & S_IFDIR)
			{
				// Attempt to create the directory.
				rc = mkdir(finishPath.c_str(), 0777);
				if (rc != 0)
				{
					return rc;
				}
			}
		}
#endif

		if (!finished)
		{
			startPath.erase(startPath.begin(), startPath.begin() + sepPos + 1);
		}

	}

	return 0;
}

void MteSdr::randomCallback(void* buffer, size_t bufferSize)
{
	(*myRandomCallback)(buffer, bufferSize);
}

void MteSdrRandomCallback(void* context, void* buffer, size_t bufferBytes)
{
	MteSdr* sdr = reinterpret_cast<MteSdr*>(context);
	sdr->randomCallback(buffer, bufferBytes);
}

bool MteSdr::isNullOrWhitespace(const std::string& s)
{
	return s.empty() || std::all_of(s.begin(), s.end(), [](unsigned char c)
		{
			return std::isspace(c);
		}
	);
}
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
#ifndef MteSdr_h
#define MteSdr_h

#include <cstdlib>
#include <memory>
#include <string>
#include <cctype>
#include <algorithm>
#include <map>
#include <fstream>
#include <list>
#if defined(WIN32) || defined(_WIN32)
#  include <Windows.h>
#  include <sysinfoapi.h>
#  include <direct.h>
#else
#  include <dirent.h>
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <cstring>
#endif

#include "mte_sdr.h"
#include "MteRandom.h"
#include "MteBase.h"

typedef void(*mte_sdr_random)(void *buff, size_t bytes);

//******************************************************************************
// Class MteSdr
//
// This is the MTE Secure Data Replacement Add-On.
//
// To use, create an object of this type. Next, call initSdr() to initialize.
// Call any of the read*() and write() methods to read and write data and
// strings. Call remove() to remove items. The entire SDR may be removed with
// removeSdr().
//
// The protected methods may be overridden to provide a different backing store
// and timestamp if desired.
//******************************************************************************
class MteSdr
{

public:

  MteSdr(mte_sdr_random rnd_cb);

  // Destructor.
  virtual ~MteSdr();

  //-----------------------------------------------------------
  // Initializes the SDR with the location and password to use.
  // Throws an exception if the SDR location cannot be created.
  //-----------------------------------------------------------
  void initSdr(const std::string &location, const uint8_t *password, size_t passwordBytes);

  void initSdr(const std::string &location, const std::string &password);

  //--------------------------------------------------
  // Read from storage or memory as data or a string.
  // If the same name exists in memory and on storage,
  // the memory version is read.
  // Throws an exception on I/O error or MTE error.
  //--------------------------------------------------
  const uint8_t *readData(const std::string &key, size_t &decryptedBytes);

  const std::string readString(const std::string &key);

  //----------------------------------------------------------------------------
  // Write the given data or string to storage or memory. If the "key" matches
  // the key of a previously written record, this will overwrite it.
  // If "toMemory" is true, the data or string is saved to memory and not
  // written to permanent storage; there are no restrictions on the contents of
  // the "key" argument.
  // If "toMemory" is false, the data or string is saved to permanent storage in
  // the SDR location set in the constructor; the "key" argument must be a
  // valid name for the given implementation.
  // The overloads that do not take the "toMemory" argument default it to false.
  //
  // Throws an exception on I/O error or MTE error.
  //----------------------------------------------------------------------------
  void write(const std::string &key, const uint8_t *value, size_t valueBytes, bool toMemory);

  void write(const std::string &key, const std::string &value);

  void write(const std::string &key, const uint8_t *value, size_t valueBytes);

  void write(const std::string &key, const std::string &value, bool toMemory);

  //-----------------------------------------------------------------------
  // Removes an SDR item. If the same name exists in memory and on storage,
  // the memory version is removed.
  //
  // It is not an error to remove an item that does not exist. An exception
  // is thrown if the record exists and cannot be removed.
  //-----------------------------------------------------------------------
  void remove(const std::string &key);

  //-------------------------------------------------------------------
  // Removes the SDR. All memory and storage items are removed.
  // This object is not usable until a new call to initSdr().
  //
  // It is not an error to remove an SDR that does not exist.
  // An exception is thrown if any record in the SDR cannot be removed.
  //-------------------------------------------------------------------
  void removeSdr();

  //------------------------------------
  // Internal function to combine a path
  // and a file name.
  //------------------------------------
  std::string static mkFilePath(const std::string &path, const std::string &file);

  // This method is public only so the C callback can access it.
  // It is not meant to be used directly.

  // The random callback.
  void randomCallback(void *buffer, size_t bufferSize);

protected:
  //--------------------------------------------------------
  // Returns true if the location exists, false if not.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  virtual bool locationExists(const std::string &location);

  //--------------------------------------------------------
  // Returns true if the record exists in the location,
  // false if not.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  virtual bool recordExists(const std::string &location,
    const std::string &key);

  //--------------------------------------------------------
  // Returns a list of records in a location.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  virtual std::list<std::string> listRecords(const std::string &location);

  //-----------------------------------------------------------
  // Creates a location (directory), including any intermediate
  // directories as necessary.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //-----------------------------------------------------------
  virtual void setupLocation(const std::string &location);

  //--------------------------------------------------------
  // Reads a record. Returns the record contents.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  virtual uint8_t *readRecord(const std::string &location, const std::string &key,
    size_t &valueBytes);

  //--------------------------------------------------------
  // Writes a record.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  virtual void writeRecord(const std::string &location, const std::string &key,
    const uint8_t *value, size_t valueBytes);

  //--------------------------------------------------------
  // Removes a location.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  virtual void removeLocation(const std::string &location);

  //--------------------------------------------------------
  // Removes a record.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  virtual void removeRecord(const std::string &location, const std::string &key);

private:
  //-------------------------------------------------------
  // Encrypts the given data. Returns the encrypted data.
  //-------------------------------------------------------
  const uint8_t *encrypt(const uint8_t *data, size_t dataBytes, size_t &encryptedBytes, mte_status &status);

  //-------------------------------------------------------
  // Decrypts the given encrypted data. Returns the decrypted data.
  //-------------------------------------------------------
  const uint8_t *decrypt(const uint8_t *encryptedData, size_t encryptedBytes, size_t &decryptedBytes, mte_status &status);


private:
  mte_sdr_random myRandomCallback;
  std::string mySdrLocation = "";
  void *myPassword;
  size_t myPasswordBytes;
  std::map<std::string, std::pair<size_t, uint8_t *> > memRecords;

  // The encoder state.
  MTE_HANDLE *myEncoder;

  // The decoder state.
  MTE_HANDLE *myDecoder;

  // Encoder buffer.
  uint8_t *myEncBuff;
  size_t myEncBuffBytes;

  // Decoder buffer.
  uint8_t *myDecBuff;
  size_t myDecBuffBytes;

  // Platform dependent path separator.
#if defined(WIN32) || defined(_WIN32)
  const static char Separator = '\\';
#else 
  const static char Separator = '/';
#endif

  static bool isNullOrWhitespace(const std::string &s);

  //-------------------------------------------------
   // Internal function to create a path, creating all
   // subdirectories as needed in the process.
   //-------------------------------------------------
  int mkAllDir(const std::string &path) const;
};

extern "C" void MteSdrRandomCallback(void *context,
  void *buffer,
  size_t  bufferBytes
);
#endif
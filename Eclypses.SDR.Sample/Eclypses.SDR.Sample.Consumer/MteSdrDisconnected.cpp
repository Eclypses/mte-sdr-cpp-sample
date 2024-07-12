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
#include "MteSdrDisconnected.h"

void MteSdrDisconnected::initSdr(const std::string security) {
	const std::string location = "";
	MteSdr::initSdr(location, security);
}

uint8_t* MteSdrDisconnected::Conceal(const uint8_t* clearData, size_t clearDataLen, size_t& protectedDataLen) {
	//
	// The key is the lookup key for this item in the data store (std::map)
	// it's value is inconsequential since this item is removed one it is used.
	//
	const std::string key = "ABCDEF";
	//
	// The location should be blank for this std::map implementation
	//
	const std::string location = "";
	//
	// This uses the MTE / SDR to conceal the clear data - as long as the revealer uses
	// the same mte library and the same security value, it can be revealed multiple times.
	// Each time the data is concealed, it will be different, so nothing can be inferred
	// from its value.
	//
	MteSdr::write(key, clearData, clearDataLen);
	//
	// This reads the protected data from the std::map and then removes it
	// leaving no trace.
	//
	uint8_t* protectedData = readRecord(location, key, protectedDataLen);
	//
	// Since we are finished with the data stored in the std::map, remove it.
	//
	removeRecord(location, key);
	//
	// Return the protected data.
	//
	return protectedData;
}

const uint8_t* MteSdrDisconnected::Reveal(const uint8_t* protectedData, size_t protectedDataLen, size_t& clearDataLen) {
	//
    // The key is the lookup key for this item in the data store (std::map)
    // it's value is inconsequential since this item is removed one it is used.
    //
	const std::string key = "ABCDEF";
	//
	// The location should be blank for this std::map implementation
	//
	const std::string location = "";
	//
	// This places the protected data into the std::map so that we
	// can get it using the SDR - this actually reveals the original value.
	//
	writeRecord(location, key, protectedData, protectedDataLen);
	//
	// This reads the data from the MTE / SDR which converts it back
	// to the original value.
	//
	const uint8_t* clearData = MteSdr::readData(key, clearDataLen);
	//
	// Since we are finished with the data stored in the std::map, remove it.
	//
	removeRecord(location, key);
	//
	// Return the clear data.
	//
	return clearData;
}
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
#pragma once
#include <MteSdr.h>
class MteSdrDisconnected : MteSdr
{
public:
	MteSdrDisconnected(mte_sdr_random rnd_cb) : MteSdr(rnd_cb) {};
    void initSdr(const std::string security);
    uint8_t* Conceal(const uint8_t* clearData, size_t clearDataLen, size_t& protectedDataLen);
    const uint8_t* Reveal(const uint8_t* protectedData, size_t protectedDataLen, size_t& clearDataLen);
protected:
    // Returns true if the location exists, false if not.
    // This simple demo implementation ignores the location.
    bool locationExists(const std::string& location) override
    {
        return !myRecords.empty();
    }

    // Returns true if the record exists in the location, false if not.
    // This simple demo implementation ignores the location.
    bool recordExists(const std::string& location, const std::string& key) override
    {
        const auto item = myRecords.find(key);
        return item != myRecords.end();
    }

    // Returns a list of file basenames in a directory.
    // Throws an exception on failure.
    // This simple demo implementation ignores the location.
    std::list<std::string> listRecords(const std::string& location) override
    {
        std::list<std::string> results;

        for (auto item : myRecords)
        {
            results.push_back(item.first);
        }
        return results;
    }

    // Sets up a location.
    // This simple demo implementation ignores the location.
    void setupLocation(const std::string& location) override
    {
        myRecords = std::map<std::string, std::pair<size_t, uint8_t*>>();
    }

    // Reads a record. Returns the record's value.
    // Throws an exception on failure.
    // This simple demo implementation ignores the location.
    uint8_t* readRecord(const std::string& location, const std::string& key,
        size_t& valueBytes) override
    {
        uint8_t* value = nullptr;
        auto encryptedMem = myRecords.find(key);
        if (encryptedMem != myRecords.end())
        {
            value = encryptedMem->second.second;
            valueBytes = encryptedMem->second.first;
        }

        return value;
    }

    // Writes a record.
    // This simple demo implementation ignores the location.
    void writeRecord(const std::string& location, const std::string& key, const uint8_t* value, size_t valueBytes) override
    {
        std::pair<size_t, uint8_t*> byteArray;
        byteArray.first = valueBytes;
        byteArray.second = new uint8_t[valueBytes];
        memcpy(byteArray.second, value, valueBytes);

        removeRecord(location, key);
        myRecords.emplace(key, byteArray);

        //hexDumpFirst128(byteArray.second, byteArray.first);
    }

    // Removes a record.
    // This simple demo implementation ignores the location.
    void removeRecord(const std::string& location, const std::string& key) override
    {
        auto item = myRecords.find(key);
        if (item != myRecords.end())
        {
            myRecords.erase(item);
        }
    }

    // Removes a location.
    // This simple demo implementation ignores the location.
    void removeLocation(const std::string& location) override
    {
        myRecords.clear();
    }

private:
	std::map<std::string, std::pair<size_t, uint8_t*> > myRecords;
};



// The MIT License (MIT)
//
// Copyright (c) Eclypses, Inc.
//
// All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
#ifndef MteMkeEnc_h
#define MteMkeEnc_h

#ifndef MteBase_h
#include "MteBase.h"
#endif

#include <string>

// Class MteMkeEnc
//
// To use as part of a dynamic library, define MTE_BUILD_SHARED and mte_EXPORTS
// when building the dynamic library; define MTE_BUILD_SHARED to use it from
// that dynamic library.
//
// This is the MTE Managed-Key Encryption encoder/encryptor.
//
// To use, create an object of this type, call instantiate(), call encode() zero
// or more times to encode each piece of data, then optionally call
// uninstantiate() to clear the random state.
//
// Alternatively, the state can be saved any time after instantiate() and
// restored instead of instantiate() to pick up at a known point.
//
// To use as a chunk-based encryptor, call startEncrypt(), call encryptChunk()
// zero or more times to encrypt each chunk of data, then finishEncrypt().
class MTE_SHARED MteMkeEnc : public MteBase
{
public:

  // Constructor using default options defined in mte_settings.h.
  MteMkeEnc();

  // Constructor taking the DRBG, token size in bytes, verifiers algorithm,
  // cipher algorithm, and hash algorithm.
  MteMkeEnc(mte_drbgs drbg,
            size_t tokBytes,
            mte_verifiers verifiers,
            mte_ciphers cipher,
            mte_hashes hash);

  // Destructor. The uninstantiate() method is called.
  virtual ~MteMkeEnc();

  // Instantiate the encoder/encryptor with the personalization string. The
  // entropy and nonce callbacks will be called to get the rest of the seeding
  // material. Returns the status.
  mte_status instantiate(const void *ps, size_t psBytes);
  mte_status instantiate(const std::string& ps);

  // Returns the reseed counter.
  MTE_UINT64_T getReseedCounter() const;

  // Returns the saved state and sets stateBytes to the length of the saved
  // state in bytes. The Base64 version returns a null-terminated Base64-encoded
  // saved state instead. On error, NULL is returned and stateBytes is set to
  // 0.
  const void *saveState(size_t& stateBytes);
  char *saveStateB64();

  // Restore a saved state, which must be the same length as was returned from
  // the saveState() call. The Base64 version takes a null-terminated Base64-
  // encoded saved state as produced by saveStateB64(). Returns the status.
  mte_status restoreState(const void *saved);
  mte_status restoreStateB64(const char *saved);

  // Returns the encode buffer size in bytes given the data length in bytes.
  size_t getBuffBytes(size_t dataBytes) const;
  size_t getBuffBytesB64(size_t dataBytes) const;

  // Encode/encrypt the given data of the given length in bytes. Returns the
  // encoded/encrypted version and sets encodedBytes to the length of the
  // encoded/ encrypted version in bytes and status to the status. The Base64
  // version returns a null-terminated Base64-encoded version instead.
  const void *encode(const void *data, size_t dataBytes,
                     size_t& encodedBytes,
                     mte_status& status);
  const char *encodeB64(const void *data, size_t dataBytes,
                        mte_status& status);

  // Encode/encrypt the given string. Returns the encoded/encrypted version and
  // sets encodedBytes to the length of the encoded/encrypted version in bytes
  // and status to the status. The Base64 version returns a null-terminated
  // Base64-encoded version instead.
  const void *encode(const std::string& str,
                     size_t& encodedBytes,
                     mte_status& status);
  const char *encodeB64(const std::string& str, mte_status& status);

  // Encode the given data of the given length at the given offset to the
  // given buffer at the given offset. Returns the status. Sets encOff to the
  // offset of the encoded version. Sets encBytes to the encoded length in
  // bytes. The encoded buffer must have sufficient length remaining after
  // the offset. Use getBuffBytes() or getBuffBytes64() to determine the
  // buffer requirement for raw or Base64 respectively.
  mte_status encode(const void *data, size_t dataOff, size_t dataBytes,
                    void *encoded, size_t& encOff, size_t& encBytes);
  mte_status encodeB64(const void *data, size_t dataOff, size_t dataBytes,
                       void *encoded, size_t& encOff, size_t& encBytes);

  // Returns the length of the result finishEncrypt() will produce. Use this if
  // you need to know that size before you can call it.
  size_t encryptFinishBytes() const;

  // Start a chunk-based encryption session. Returns the status.
  mte_status startEncrypt();

  // Encrypt a chunk of data in a chunk-based encryption session. The data is
  // encrypted in place. The dataBytes must be a multiple of the chosen cipher's
  // block size. Returns the status.
  mte_status encryptChunk(void *data, size_t dataBytes);

  // Finish a chunk-based encryption session. Returns the final part of the
  // result and sets resultBytes to the length of the final part and status to
  // the status.
  const void *finishEncrypt(size_t& resultBytes, mte_status& status);

  // Uninstantiate the encoder/encryptor. It is no longer usable after this
  // call. Returns the status.
  mte_status uninstantiate();

private:

  // Copy constructor and assignment operator not implemented.
  MteMkeEnc(const MteMkeEnc&);
  MteMkeEnc& operator=(const MteMkeEnc&);

  // Initialize.
  void init(mte_drbgs drbg,
            size_t tokBytes,
            mte_verifiers verifiers,
            mte_ciphers cipher,
            mte_hashes hash);

private:

  // The encoder/encryptor state.
  MTE_UINT8_T *myEncoder;

  // Encoder buffer.
  char *myEncBuff;
  size_t myEncBuffBytes;

  // State save buffer.
  char *mySaveBuff;
  size_t mySaveBytes;
};

#endif


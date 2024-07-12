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
#ifndef MteMkeDec_h
#define MteMkeDec_h

#ifndef MteBase_h
#include "MteBase.h"
#endif

#include <string>

// Class MteMkeDec
//
// To use as part of a dynamic library, define MTE_BUILD_SHARED and mte_EXPORTS
// when building the dynamic library; define MTE_BUILD_SHARED to use it from
// that dynamic library.
//
// This is the MTE Managed-Key Encryption decoder/decryptor.
//
// To use, create an object of this type, call instantiate(), call decode() zero
// or more times to decode/decrypt each encoded data, then optionally call
// uninstantiate() to clear the random state.
//
// Alternatively, the state can be saved any time after instantiate() and
// restored instead of instantiate() to pick up at a known point.
//
// To use as a chunk-based decryptor, call startDecrypt(), call decryptChunk()
// zero or more times to decrypt each chunk of data, then finishDecrypt().
class MTE_SHARED MteMkeDec : public MteBase
{
public:

  // Constructor using default options defined in mte_settings.h.
  //
  // The timestamp window and sequence window are optionally settable.
  MteMkeDec(MTE_UINT64_T tWindow = 0, MTE_INT32_T sWindow = 0);

  // Constructor taking the DRBG, token size in bytes, verifiers algorithm,
  // cipher algorithm, hash algorithm, timestamp window, and sequence window.
  MteMkeDec(mte_drbgs drbg,
            size_t tokBytes,
            mte_verifiers verifiers,
            mte_ciphers cipher,
            mte_hashes hash,
            MTE_UINT64_T tWindow,
            MTE_INT32_T sWindow);

  // Destructor. The uninstantiate() method is called.
  virtual ~MteMkeDec();

  // Initialize the decoder/decryptor with the personalization string. The
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

  // Returns the decode buffer size in bytes given the encoded data length in
  // bytes.
  size_t getBuffBytes(size_t encodedBytes) const;
  size_t getBuffBytesB64(size_t encodedBytes) const;

  // Decodes/decrypts the given encoded/encrypted version of the given length
  // in bytes. Returns the decoded/decrypted data and sets decodedBytes to the
  // length of the decoded/decrypted data in bytes and status to the status.
  // The Base64 version takes a null-terminated Base64-encoded version.
  void *decode(const void *encoded, size_t encodedBytes,
               size_t& decodedBytes,
               mte_status& status);
  void *decodeB64(const char *encoded,
                  size_t& decodedBytes,
                  mte_status& status);

  // Decode/decrypt the given encoded/encrypted version to a string. Returns
  // the status. The Base64 version takes a null-terminated Base64-encoded
  // version.
  mte_status decode(const void *encoded, size_t encodedBytes, std::string& str);
  mte_status decodeB64(const char *encoded, std::string& str);

  // Decode the given encoded version of the given length at the given offset to
  // the given buffer at the given offset. Returns the status. Sets decOff to
  // the offset of the decoded version. Sets decBytes to the decoded length in
  // bytes. The decoded buffer must have sufficient length remaining after
  // the offset. Use getBuffBytes() or getBuffBytes64() to determine the
  // buffer requirement for raw or Base64 respectively.
  mte_status decode(const void *encoded, size_t encOff, size_t encBytes,
                    void *decoded, size_t& decOff, size_t& decBytes);
  mte_status decodeB64(const void *encoded, size_t encOff, size_t encBytes,
                       void *decoded, size_t& decOff, size_t& decBytes);

  // Start a chunk-based decryption session. Returns the status.
  mte_status startDecrypt();

  // Decrypt a chunk of data in a chunk-based decryption session. Returns the
  // decrypted data and sets decryptedBytes to the amount decrypted. Returns
  // NULL on error.
  const void *decryptChunk(const void *encrypted, size_t encryptedBytes,
                           size_t& decryptedBytes);

  // Decrypt a chunk of data at the given offset of the given length in a
  // chunk-based decryption session. Some decrypted data is written to the
  // decrypted buffer starting at decOff. The amount decrypted is returned.
  // Returns ULONG_MAX on error.
  size_t decryptChunk(const void *encrypted, size_t encOff, size_t encBytes,
                      void *decrypted, size_t decOff);

  // Finish a chunk-based decryption session. Returns the final part of the
  // result and sets decryptedBytes to the length of the final part and status
  // to the status.
  const void *finishDecrypt(size_t& decryptedBytes, mte_status& status);

  // Returns the timestamp set during encoding or 0 if there is no timestamp.
  MTE_UINT64_T getEncTs() const;

  // Returns the timestamp set during decoding or 0 if there is no timestamp.
  MTE_UINT64_T getDecTs() const;

  // Returns the number of messages that were skipped to get in sync during the
  // decode or 0 if there is no sequencing.
  MTE_UINT32_T getMsgSkipped() const;

  // Uninstantiate the decoder/decryptor. It is no longer usable after this
  // call. Returns the status.
  mte_status uninstantiate();

private:

  // Copy constructor and assignment operator not implemented.
  MteMkeDec(const MteMkeDec&);
  MteMkeDec& operator=(const MteMkeDec&);

  // Initialize.
  void init(mte_drbgs drbg,
            size_t tokBytes,
            mte_verifiers verifiers,
            mte_ciphers cipher,
            mte_hashes hash,
            MTE_UINT64_T tWindow,
            MTE_INT32_T sWindow);

private:

  // The decoder state.
  MTE_UINT8_T *myDecoder;

  // Decoder buffer.
  char *myDecBuff;
  size_t myDecBuffBytes;
  mte_dec_args myDecArgs;

  // State save buffer.
  char *mySaveBuff;
  size_t mySaveBytes;

  // Decrypt state.
#if !defined(MTE_BUILD_MINSIZEREL)
  size_t myCiphBlockBytes;
#endif
  MTE_UINT8_T *myDecryptor;
};

#endif


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
#ifndef MteBase_h
#define MteBase_h

#ifndef mte_base_h
#include "mte_base.h"
#endif

#include <cstdlib>

// Class MteBase
//
// To use as part of a dynamic library, define MTE_BUILD_SHARED and mte_EXPORTS
// when building the dynamic library; define MTE_BUILD_SHARED to use it from
// that dynamic library.
//
// This is the base for all MTE classes.
//
// To use, call any of the static helper functions and/or derive from this
// class.
//
// The MTE initialization is automatically performed unless built with
// MTE_SKIP_AUTO_INIT defined, in which case you must do the initialization
// yourself.
class MTE_SHARED MteBase
{
public:

  // Returns the MTE version number as a string or individual integer parts.
  static const char *getVersion();
  static size_t getVersionMajor();
  static size_t getVersionMinor();
  static size_t getVersionPatch();

  // Initialize with the company name and license code. Returns true if
  // successful or false if not. If true is returned, MTE functions are usable;
  // otherwise functions that return a status will return an error status.
  static bool initLicense(const char *company, const char *license);

  // Returns the count of status codes.
  static size_t getStatusCount();

  // Returns the enumeration name for the given status.
  static const char *getStatusName(mte_status status);

  // Returns the description for the given status.
  static const char *getStatusDescription(mte_status status);

  // Returns the status code for the given enumeration name.
  static mte_status getStatusCode(const char *name);

  // Returns true if the given status is an error, false if it is success or a
  // warning.
  static bool statusIsError(mte_status status);

  // Returns true if runtime options are available or false if not.
  static bool hasRuntimeOpts();

  // Returns the default DRBG. If runtime options are not available, this is
  // the only option available; otherwise it is a suitable default.
  static mte_drbgs getDefaultDrbg();

  // Returns the default token size. If runtime options are not available, this
  // is the only option available; otherwise it is a suitable default.
  static size_t getDefaultTokBytes();

  // Returns the default verifiers. If runtime options are not available, this
  // is the only option available; otherwise it is a suitable default.
  static mte_verifiers getDefaultVerifiers();

  // Returns the default cipher. If runtime options are not available, this is
  // the only option available; otherwise it is a suitable default.
  static mte_ciphers getDefaultCipher();

  // Returns the default hash. If runtime options are not available, this is
  // the only option available; otherwise it is a suitable default.
  static mte_hashes getDefaultHash();

  // Returns the count of DRBG algorithms.
  static size_t getDrbgsCount();

  // Returns the enumeration name for the given algorithm.
  static const char *getDrbgsName(mte_drbgs algo);

  // Returns the algorithm for the given enumeration name.
  static mte_drbgs getDrbgsAlgo(const char *name);

  // Returns the security strength for the given algorithm.
  static size_t getDrbgsSecStrengthBytes(mte_drbgs algo);

  // Returns the minimum/maximum personalization string size for the given
  // algorithm.
  static size_t getDrbgsPersonalMinBytes(mte_drbgs algo);
  static size_t getDrbgsPersonalMaxBytes(mte_drbgs algo);

  // Returns the minimum/maximum entropy size for the given algorithm.
  static size_t getDrbgsEntropyMinBytes(mte_drbgs algo);
  static size_t getDrbgsEntropyMaxBytes(mte_drbgs algo);

  // Returns the minimum/maximum nonce size for the given algorithm.
  static size_t getDrbgsNonceMinBytes(mte_drbgs algo);
  static size_t getDrbgsNonceMaxBytes(mte_drbgs algo);

  // Returns the reseed interval for the given algorithm.
  static MTE_UINT64_T getDrbgsReseedInterval(mte_drbgs algo);

  // Set the increment DRBG to return an error during instantiation and
  // uninstantiation (if true) or not (if false). This is useful for testing
  // error handling. The flag is false until set with this.
  static void setIncrInstError(bool flag);

  // Set the increment DRBG to produce an error after the given number of values
  // have been generated (if flag is true) or turn off errors (if flag is false)
  // other than the reseed error, which is always produced when the seed
  // interval is reached. The flag is false until set with this.
  static void setIncrGenError(bool flag, size_t after);

  // Returns the count of verifier algorithms.
  static size_t getVerifiersCount();

  // Returns the enumeration name for the given algorithm.
  static const char *getVerifiersName(mte_verifiers algo);

  // Returns the algorithm for the given enumeration name.
  static mte_verifiers getVerifiersAlgo(const char *name);

  // Returns the count of cipher algorithms.
  static size_t getCiphersCount();

  // Returns the enumeration name for the given algorithm.
  static const char *getCiphersName(mte_ciphers algo);

  // Returns the algorithm for the given enumeration name.
  static mte_ciphers getCiphersAlgo(const char *name);

  // Returns the block size for the given algorithm.
  static size_t getCiphersBlockBytes(mte_ciphers algo);

  // Returns the count of hash algorithms.
  static size_t getHashesCount();

  // Returns the enumeration name for the given algorithm.
  static const char *getHashesName(mte_hashes algo);

  // Returns the algorithm for the given enumeration name.
  static mte_hashes getHashesAlgo(const char *name);

public:

  // Interface of an entropy input callback.
  class EntropyCallback
  {
  public:
    // Destructor.
    virtual ~EntropyCallback();

    // The entropy callback.
    virtual mte_status entropyCallback(mte_drbg_ei_info& info) = 0;
  };

  // Interface of a nonce callback.
  class NonceCallback
  {
  public:
    // Destructor.
    virtual ~NonceCallback();

    // The nonce callback.
    virtual void nonceCallback(mte_drbg_nonce_info& info) = 0;
  };

  // Interface of a timestamp callback.
  class TimestampCallback
  {
  public:
    // Destructor.
    virtual ~TimestampCallback();

    // The timestamp callback.
    virtual MTE_UINT64_T timestampCallback() = 0;
  };

public:

  // Constructor. Derived classes must call initBase() from their constructor.
  MteBase();

  // Destructor.
  virtual ~MteBase();

  // Return the options in use.
  mte_drbgs getDrbg() const;
  size_t getTokBytes() const;
  mte_verifiers getVerifiers() const;
  mte_ciphers getCipher() const;
  mte_hashes getHash() const;

  // Set the entropy callback. If not NULL, it is called to get entropy. If
  // NULL, the entropy set with setEntropy() is used. No ownership is taken.
  // The cb object must remain valid for the lifetime of this object.
  void setEntropyCallback(EntropyCallback *cb);

  // Set the entropy input value. This must be done before calling an
  // instantiation method that will trigger the entropy callback. The
  // value must remain valid until instantiation completes.
  //
  // The entropy is zeroized when used by an instantiation call.
  //
  // All ownership remains with the caller. If the entropy callback is NULL,
  // entropyInput is used as the entropy.
  void setEntropy(void *entropyInput, size_t eiBytes);

  // Set the nonce callback. If not NULL, it is used to get the nonce. If NULL,
  // the nonce set with setNonce() is used. No ownership is taken. The cb
  // object must remain valid for the lifetime of this object.
  void setNonceCallback(NonceCallback *cb);

  // Set the nonce. This must be done before calling an instantiation method
  // that will trigger the nonce callback.
  //
  // All ownership remains with the caller. If the nonce callback is NULL,
  // nonce is used as the nonce.
  void setNonce(const void *nonce, size_t nBytes);

  // Calls setNonce() with the nonce value as an array of bytes in little
  // endian format.
  void setNonce(MTE_UINT64_T nonce);

  // Set the timestamp callback. If not NULL, it is called to get the timestamp.
  // If NULL, 0 is used. No ownership is taken. The cb object must remain valid
  // for the lifetime of this object.
  void setTimestampCallback(TimestampCallback *cb);

public:

  // These methods are public only so the C callback can access them. They are
  // not meant to be used directly.

  // The entropy callback.
  mte_status entropyCallback(mte_drbg_ei_info& info);

  // The nonce callback.
  void nonceCallback(mte_drbg_nonce_info& info);

  // The timestamp callback.
  MTE_UINT64_T timestampCallback();

protected:

  // Initialize.
  void initBase(mte_drbgs drbg,
                size_t tokBytes,
                mte_verifiers verifiers,
                mte_ciphers cipher,
                mte_hashes hash);

private:

  // Options.
  mte_drbgs myDrbg;
  size_t myTokBytes;
  mte_verifiers myVerifiers;
  mte_ciphers myCipher;
  mte_hashes myHash;

  // Callbacks.
  EntropyCallback *myEntropyCb;
  NonceCallback *myNonceCb;
  TimestampCallback *myTimestampCb;

  // Instantiation inputs.
  void *myEntropyInput;
  size_t myEntropyInputBytes;
  const void *myNonce;
  size_t myNonceBytes;
  MTE_UINT8_T myNonceBuff[32];

  // Nonce length when set as an integer.
  size_t myNonceIntBytes;

private:

#ifndef MTE_SKIP_AUTO_INIT
  // The static initializer to initialize MTE.
  class Init
  {
  public:
    Init();
  };
  static const Init ourInit;
#endif

private:

  // Copy constructor and assignment operator not implemented.
  MteBase(const MteBase&);
  MteBase& operator=(const MteBase&);
};

// C callbacks.
extern "C"
{
  mte_status MteBaseEntropyCallback(void *context, mte_drbg_ei_info *info);
  void MteBaseNonceCallback(void *context, mte_drbg_nonce_info *info);
  MTE_UINT64_T MteBaseTimestampCallback(void *context);
}

#endif


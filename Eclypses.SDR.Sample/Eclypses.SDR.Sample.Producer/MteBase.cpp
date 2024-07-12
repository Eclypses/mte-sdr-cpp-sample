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
#include "MteBase.h"
#endif
#ifndef mte_init_h
#include "mte_init.h"
#endif
#ifndef mte_license_h
#include "mte_license.h"
#endif
#ifndef mte_version_h
#include "mte_version.h"
#endif

#include <algorithm>
#include <cstring>
#include <stdexcept>

const char *MteBase::getVersion()
{
  return mte_base_version();
}

size_t MteBase::getVersionMajor()
{
  return MTE_VERSION_MAJOR;
}

size_t MteBase::getVersionMinor()
{
  return MTE_VERSION_MINOR;
}

size_t MteBase::getVersionPatch()
{
  return MTE_VERSION_PATCH;
}

bool MteBase::initLicense(const char *company, const char *license)
{
  return mte_license_init(company, license) != MTE_FALSE;
}

size_t MteBase::getStatusCount()
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_status_count();
#else
  return 0;
#endif
}

const char *MteBase::getStatusName(mte_status status)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_status_name(status);
#else
  (void)status;
  return NULL;
#endif
}

const char *MteBase::getStatusDescription(mte_status status)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_status_description(status);
#else
  (void)status;
  return NULL;
#endif
}

mte_status MteBase::getStatusCode(const char *name)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_status_code(name);
#else
  (void)name;
  return static_cast<mte_status>(-1);
#endif
}

bool MteBase::statusIsError(mte_status status)
{
  return mte_base_status_is_error(status) != MTE_FALSE;
}

bool MteBase::hasRuntimeOpts()
{
  return !!MTE_RUNTIME;
}

mte_drbgs MteBase::getDefaultDrbg()
{
  return MTE_DRBG_ENUM;
}

size_t MteBase::getDefaultTokBytes()
{
  return MTE_TOKBYTES;
}

mte_verifiers MteBase::getDefaultVerifiers()
{
  return MTE_VERIFIERS_ENUM;
}

mte_ciphers MteBase::getDefaultCipher()
{
  return MTE_CIPHER_ENUM;
}

mte_hashes MteBase::getDefaultHash()
{
  return MTE_HASH_ENUM;
}

size_t MteBase::getDrbgsCount()
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_count();
#else
  return 0;
#endif
}

const char *MteBase::getDrbgsName(mte_drbgs algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_name(algo);
#else
  (void)algo;
  return NULL;
#endif
}

mte_drbgs MteBase::getDrbgsAlgo(const char *name)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_algo(name);
#else
  (void)name;
  return static_cast<mte_drbgs>(-1);
#endif
}

size_t MteBase::getDrbgsSecStrengthBytes(mte_drbgs algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_sec_strength_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

size_t MteBase::getDrbgsPersonalMinBytes(mte_drbgs algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_personal_min_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

size_t MteBase::getDrbgsPersonalMaxBytes(mte_drbgs algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_personal_max_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

size_t MteBase::getDrbgsEntropyMinBytes(mte_drbgs algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_entropy_min_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

size_t MteBase::getDrbgsEntropyMaxBytes(mte_drbgs algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_entropy_max_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

size_t MteBase::getDrbgsNonceMinBytes(mte_drbgs algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_nonce_min_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

size_t MteBase::getDrbgsNonceMaxBytes(mte_drbgs algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_nonce_max_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

MTE_UINT64_T MteBase::getDrbgsReseedInterval(mte_drbgs algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_reseed_interval(algo);
#else
  (void)algo;
  return 0;
#endif
}

void MteBase::setIncrInstError(bool flag)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  mte_base_drbgs_incr_inst_error(flag);
#else
  (void)flag;
#endif
}

void MteBase::setIncrGenError(bool flag, size_t after)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  mte_base_drbgs_incr_gen_error(flag, static_cast<MTE_SIZE_T>(after));
#else
  (void)flag;
  (void)after;
#endif
}

size_t MteBase::getVerifiersCount()
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_verifiers_count();
#else
  return 0;
#endif
}

const char *MteBase::getVerifiersName(mte_verifiers algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_verifiers_name(algo);
#else
  (void)algo;
  return NULL;
#endif
}

mte_verifiers MteBase::getVerifiersAlgo(const char *name)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_verifiers_algo(name);
#else
  (void)name;
  return static_cast<mte_verifiers>(-1);
#endif
}

size_t MteBase::getCiphersCount()
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_ciphers_count();
#else
  return 0;
#endif
}

const char *MteBase::getCiphersName(mte_ciphers algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_ciphers_name(algo);
#else
  (void)algo;
  return NULL;
#endif
}

mte_ciphers MteBase::getCiphersAlgo(const char *name)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_ciphers_algo(name);
#else
  (void)name;
  return static_cast<mte_ciphers>(-1);
#endif
}

size_t MteBase::getCiphersBlockBytes(mte_ciphers algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_ciphers_block_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

size_t MteBase::getHashesCount()
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_hashes_count();
#else
  return 0;
#endif
}

const char *MteBase::getHashesName(mte_hashes algo)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_hashes_name(algo);
#else
  (void)algo;
  return NULL;
#endif
}

mte_hashes MteBase::getHashesAlgo(const char *name)
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_hashes_algo(name);
#else
  (void)name;
  return static_cast<mte_hashes>(-1);
#endif
}

MteBase::EntropyCallback::~EntropyCallback()
{
  // Nothing to do here.
}

MteBase::NonceCallback::~NonceCallback()
{
  // Nothing to do here.
}

MteBase::TimestampCallback::~TimestampCallback()
{
  // Nothing to do here.
}

MteBase::MteBase() :
  myEntropyCb(NULL),
  myNonceCb(NULL),
  myTimestampCb(NULL),
  myEntropyInput(NULL),
  myEntropyInputBytes(0),
  myNonce(NULL),
  myNonceBytes(0)
{
  // Nothing to do here.
}

MteBase::~MteBase()
{
  // Nothing to do here.
}

mte_drbgs MteBase::getDrbg() const
{
  return myDrbg;
}

size_t MteBase::getTokBytes() const
{
  return myTokBytes;
}

mte_verifiers MteBase::getVerifiers() const
{
  return myVerifiers;
}

mte_ciphers MteBase::getCipher() const
{
  return myCipher;
}

mte_hashes MteBase::getHash() const
{
  return myHash;
}

void MteBase::setEntropyCallback(EntropyCallback *cb)
{
  myEntropyCb = cb;
}

void MteBase::setEntropy(void *entropyInput, size_t eiBytes)
{
  myEntropyInput = entropyInput;
  myEntropyInputBytes = eiBytes;
}

void MteBase::setNonceCallback(NonceCallback *cb)
{
  myNonceCb = cb;
}

void MteBase::setNonce(const void *nonce, size_t nBytes)
{
  myNonce = nonce;
  myNonceBytes = nBytes;
}

void MteBase::setNonce(MTE_UINT64_T nonce)
{
  // Copy the bytes of the nonce in little endian.
  size_t i = 0;
  for (; i < sizeof(nonce); ++i)
  {
    myNonceBuff[i] = static_cast<MTE_UINT8_T>(nonce >> (i * 8));
  }

  // If the nonce must be longer, zero pad.
  for (; i < myNonceIntBytes; ++i)
  {
    myNonceBuff[i] = 0;
  }

  // Set the nonce to the ideal size.
  setNonce(myNonceBuff, myNonceIntBytes);
}

void MteBase::setTimestampCallback(TimestampCallback *cb)
{
  myTimestampCb = cb;
}

mte_status MteBase::entropyCallback(mte_drbg_ei_info& info)
{
  // Call the callback if set.
  if (myEntropyCb != NULL)
  {
    return myEntropyCb->entropyCallback(info);
  }

  // Check the length.
  if (myEntropyInputBytes < info.min_length ||
      myEntropyInputBytes > info.max_length)
  {
    return mte_status_drbg_catastrophic;
  }

  // Just point at the entropy buffer.
  info.buff = reinterpret_cast<MTE_UINT8_T *>(myEntropyInput);

  // Success.
  info.bytes = static_cast<MTE_SIZE_T>(myEntropyInputBytes);
  return mte_status_success;
}

void MteBase::nonceCallback(mte_drbg_nonce_info& info)
{
  // Call the callback if set.
  if (myNonceCb != NULL)
  {
    myNonceCb->nonceCallback(info);
    return;
  }

  // Copy to the provided buffer.
  info.bytes = static_cast<MTE_SIZE8_T>(myNonceBytes);
  memcpy(info.buff, myNonce, myNonceBytes);
}

MTE_UINT64_T MteBase::timestampCallback()
{
  // Call the callback if set.
  if (myTimestampCb != NULL)
  {
    return myTimestampCb->timestampCallback();
  }

  // Default to 0 otherwise.
  return 0;
}

void MteBase::initBase(mte_drbgs drbg,
                       size_t tokBytes,
                       mte_verifiers verifiers,
                       mte_ciphers cipher,
                       mte_hashes hash)
{
  // Set the options.
  myDrbg = drbg;
  myTokBytes = tokBytes;
  myVerifiers = verifiers;
  myCipher = cipher;
  myHash = hash;

  // The ideal nonce length is the size of the nonce integer, but it must be at
  // least the minimum for the DRBG and no more than the maximum for the DRBG.
  myNonceIntBytes = std::max(getDrbgsNonceMinBytes(drbg),
                             std::min(sizeof(MTE_UINT64_T),
                                      getDrbgsNonceMaxBytes(drbg)));
}

#ifndef MTE_SKIP_AUTO_INIT
MteBase::Init::Init()
{
  // Do global init.
  if (!mte_init(NULL, NULL))
  {
    throw std::runtime_error("MTE init error.");
  }

  // Check version.
  char *end;
  if (strtoul(getVersion(), &end, 10) != MTE_VERSION_MAJOR ||
      strtoul(end + 1, &end, 10) != MTE_VERSION_MINOR ||
      strtoul(end + 1, &end, 10) != MTE_VERSION_PATCH)
  {
    throw std::runtime_error("MTE version mismatch.");
  }
}
const MteBase::Init MteBase::ourInit;
#endif

extern "C"
{
  mte_status MteBaseEntropyCallback(void *context, mte_drbg_ei_info *info)
  {
    MteBase *base = reinterpret_cast<MteBase *>(context);
    return base->entropyCallback(*info);
  }

  void MteBaseNonceCallback(void *context, mte_drbg_nonce_info *info)
  {
    MteBase *base = reinterpret_cast<MteBase *>(context);
    base->nonceCallback(*info);
  }

  MTE_UINT64_T MteBaseTimestampCallback(void *context)
  {
    MteBase *base = reinterpret_cast<MteBase *>(context);
    return base->timestampCallback();
  }
}


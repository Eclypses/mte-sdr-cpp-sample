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
#ifndef MteKyber_h
#define MteKyber_h

#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include "mte_kyber.h"
#include "mte_alloca.h"

typedef enum KyberStrength
{
    None = 0,
    K512 = 512,
    K768 = 768,
    K1024 = 1024
} KyberStrength;

class MteKyber
{

public:
    const static int Success = 0;
    const static int InvalidStrength = -1;
    const static int EntropyFail = -2;
    const static int InvalidPubKey = -3;
    const static int InvalidPrivKey = -4;
    const static int MemoryFail = -5;
    const static int InvalidCypherText = -6;

protected:
    static size_t minEntropySize;
    static size_t maxEntropySize;
    static size_t publicKeySize;
    static size_t privateKeySize;
    static size_t secretSize;
    static size_t encryptedSize;
    uint8_t* myEntropyInput;
    size_t myEntropyInputBytes;
    static KyberStrength globalKyberStrength;

public:

    /// <summary>
    /// Initialize kyber with the provided strength.
    /// </summary>
    /// <param name="strength">The strength of the kyber protocol.</param>
    /// <returns>The result of initializing kyber.</returns>
    static int init(KyberStrength strength);

    // Constructor. Will not be fully useable until set with init.
    MteKyber();

    // Destructor.
    virtual ~MteKyber();


    /// <summary>
    /// Generate a Kyber key pair. The buffer publicKey will need to have been set to the size using MteKyber::getPublicKeySize().
    /// </summary>
    /// <param name="publicKey">The public key to be sent to the responder.</param>
    /// <param name="publicKeyBytes">The size in bytes of the public key.</param>
    /// <returns>The result of creating the key pair.</returns>
    int createKeyPair(void* publicKey, size_t& publicKeyBytes);

    /// <summary>
    /// Compute the Kyber secret and the encrypted secret.
    /// </summary>
    /// <param name="peerPublicKey">The peer's public key.</param>
    /// <param name="peerPublicKeyBytes">The size in bytes of the peer's public key.</param>
    /// <param name="secret">The secret to be used.</param>
    /// <param name="secretBytes">The size in bytes of the secret.</param>
    /// <param name="encrypted">The encrypted to be sent to the initiator.</param>
    /// <param name="encryptedBytes">The size in bytes of the encrypted.</param>
    /// <returns>The result of generating an encrypted output and secret.</returns>
    int createSecret(const void* peerPublicKey, size_t peerPublicKeyBytes,
        void* secret, size_t& secretBytes,
        void* encrypted, size_t& encryptedBytes);

    /// <summary>
    /// Decrypt the Kyber secret.
    /// </summary>
    /// <param name="encrypted">The encrypted from the initiator.</param>
    /// <param name="encryptedBytes">The size in bytes of the encrypted.</param>
    /// <param name="secret">The secret to be used.</param>
    /// <param name="secretBytes">The size in bytes of the secret.</param>
    /// <returns>The result of decrypting the provided encrypted buffer.</returns>
    int decryptSecret(const void* encrypted, size_t encryptedBytes,
        void* secret, size_t& secretBytes);

    /// <summary>
    /// Sets the entropy.
    /// </summary>
    /// <param name="entropy">The entropy buffer.</param>
    /// <param name="entropyBytes">The size in bytes of the entropy buffer.</param>
    /// <returns>The result of setting entropy.</returns>
    int setEntropy(void* entropy, size_t entropyBytes);

    class EntropyCallback
    {

    public:
        virtual ~EntropyCallback();
        virtual int entropyCallback(void** entropy, size_t* entropyBytes, size_t minEntropyBytes, size_t maxEntropyBytes) = 0;
    };

    /// <summary>
    /// Sets the entropy callback function.
    /// </summary>
    /// <param name="cb">The callback function.</param>
    void setEntropyCallback(EntropyCallback* cb);

    // This method is public only so the C callback can access it.
    // It is not meant to be used directly.

    // The entropy callback.
    int entropyCallback(void** entropy, size_t* entropyBytes, size_t minEntropyBytes, size_t maxEntropyBytes);

    /// <summary>
    /// Gets the public key size. init() should be successfully called first.
    /// </summary>
    /// <returns>The size of the public key or 0 if init is missing.</returns>
    static size_t getPublicKeySize();

    /// <summary>
    /// Gets the min entropy size. init() should be successfully called first.
    /// </summary>
    /// <returns>The min size of the entropy or 0 if init is missing.</returns>
    static size_t getMinEntropySize();

    /// <summary>
    /// Gets the max entropy size. init() should be successfully called first.
    /// </summary>
    /// <returns>The max size of the entropy or 0 if init is missing.</returns>
    static size_t getMaxEntropySize();

    /// <summary>
    /// Gets the secret size. init() should be successfully called first.
    /// </summary>
    /// <returns>The size of the secret or 0 if init is missing.</returns>
    static size_t getSecretSize();

    /// <summary>
    /// Gets the encrypted size. init() should be successfully called first.
    /// </summary>
    /// <returns>The size of the encrypted or 0 if init is missing.</returns>
    static size_t getEncryptedSize();

    /// <summary>
    /// Get the name of the current algorithm used.
    /// </summary>
    /// <returns>The name of the current Kyber algorithm.</returns>
    static char* getAlgorithm();

    /// <summary>
    /// Helper function for zeroizing data.
    /// </summary>
    /// <param name="dest">The destination buffer.</param>
    /// <param name="size">The size in bytes of the destination buffer.</param>
    static void zeroize(void* dest, size_t size);

protected:
    uint8_t* myPrivateKey;
    size_t myPrivateKeyBytes;
    uint8_t* myPublicKey;
    size_t myPublicKeyBytes;

private:
    bool hasCreatedKeys = false;
    EntropyCallback* myEntropyCb;
};

extern "C" int MteKyberEntropyCallback(void* context,
    void** entropy,
    size_t * entropyBytes,
    size_t minEntropyBytes,
    size_t maxEntropyBytes
);

#endif
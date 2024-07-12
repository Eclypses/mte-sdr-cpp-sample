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
#if defined(_WIN32)
#  include <Windows.h>
#  include <NTSecAPI.h>
#  include <bcrypt.h>
#elif defined(linux) || defined(__linux__) || \
      defined(ANDROID) || defined(__APPLE__)
#  include "stdio.h"
#  include "errno.h"
#endif

#include "mte_random.h"



/****************************************************************************
 * Generate random numbers using the OS supplied RNG. If the OS platform
 * is unknown, this code will not compile.
 *
 * [out] buffer: the buffer to be filled with random bytes
 * [in] bytes:   size of buffer in bytes
 *
 * return:  0 on success
 *          If there was an error, the value is platform dependent
 ****************************************************************************/
int mte_random(void *buffer, size_t bytes) {
#if defined(_WIN32)
  /* "BCryptGenRandom" returns a "NTSTATUS" which is defined in the
     Windows DDK. "NTSTATUS" is nothing more than a 32-bit unsigned
     integer. We use "ULONG" instead which is Windows API data type.
     Also note that the NTSTATUS values are defined in the DDK.   */
  if ((bytes == 0) || (buffer == NULL))
    /* Returning an artificial STATUS_INVALID_PARAMETER here */
    return (int)LsaNtStatusToWinError(0xC000000D);
  ULONG status = BCryptGenRandom(NULL, buffer, (ULONG)bytes,
                                 BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status == 0)
    return 0;
  else
    return (int)LsaNtStatusToWinError(status);
#elif defined(linux) || defined(__linux__) || \
      defined(ANDROID) || defined(__APPLE__)
  if ((bytes == 0) || (buffer == NULL))
    return EINVAL;
  FILE *rng = fopen("/dev/urandom", "rb");
  size_t result = fread(buffer, bytes, 1, rng);
  fclose(rng);
  return (result == 1) ? 0 : errno;
#else
#  error unknown platform; cannot compile mte_random()
#endif
}



/****************************************************************************
 * Generate random numbers using the OS supplied RNG. If the OS platform
 * is unknown, this code will not compile.
 * This variant is the callback version used by the Diffie-Hellman and
 * Kyber key exchange modules.
 *
 * [in] context: used by key exchange module language interfaces
 * [out] buffer: the buffer to be filled with random bytes
 * [in] bytes:   size of buffer in bytes
 *
 * return:  0 on success
 *          If there was an error, the value is platform dependent
 ****************************************************************************/
int mte_random_callback(void *context, void *buffer, size_t bytes) {
  (void)context;
  return mte_random(buffer, bytes);
}

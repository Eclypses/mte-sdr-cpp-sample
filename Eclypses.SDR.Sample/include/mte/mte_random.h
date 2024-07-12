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
#ifndef mte_random_h
#define mte_random_h

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif



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
extern int mte_random(void *buffer, size_t bytes);



/****************************************************************************
 * Generate random numbers using the OS supplied RNG. If the OS platform
 * is unknown, this code will not compile.
 * This variant is the callback version used by the Diffie-Hellman and
 * Kyber key exchange mechanisms.
 *
 * [out] buffer: the buffer to be filled with random bytes
 * [in] bytes:   size of buffer in bytes
 *
 * return:  0 on success
 *          If there was an error, the value is platform dependent
 ****************************************************************************/
extern int mte_random_callback(void *context, void *buffer, size_t bytes);



#ifdef __cplusplus
}
#endif

#endif /* mte_random_h */

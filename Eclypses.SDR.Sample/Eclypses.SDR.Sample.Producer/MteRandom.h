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
#ifndef MTERANDOM_H
#define MTERANDOM_H

#include "mte_random.h"



// Class MteRandom
//
// To use as part of a dynamic library, define MTE_BUILD_SHARED and mte_EXPORTS
// when building the dynamic library; define MTE_BUILD_SHARED to use it from
// that dynamic library.
//
// To use, call the static "getBytes" method. Instantiation is unnecessary.
//
class MTE_SHARED MteRandom {
public:

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
  static int getBytes(void* buffer, size_t bytes) {
    return mte_random(buffer, bytes);
  }
  
};

#endif


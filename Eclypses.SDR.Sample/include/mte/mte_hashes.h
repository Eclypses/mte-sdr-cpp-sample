/* Copyright (c) Eclypses, Inc. */
/*  */
/* All rights reserved. */
/*  */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. */
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */

/* WARNING: This file is automatically generated. Do not edit. */

#ifndef mte_hashes_h
#define mte_hashes_h

#ifdef __cplusplus
extern "C"
{
#endif

/* Hash algorithms. */
typedef enum mte_hashes_
{
  /* None. An external hash may be provided instead. */
  mte_hashes_none,

  /* CRC-32 */
  mte_hashes_crc32,

  /* SHA-1 */
  mte_hashes_sha1,

  /* SHA-256 */
  mte_hashes_sha256,

  /* SHA-512 */
  mte_hashes_sha512
} mte_hashes;

#ifdef __cplusplus
}
#endif

#endif


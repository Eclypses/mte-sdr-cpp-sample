/*
Copyright (c) Eclypses, Inc.

All rights reserved.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#ifndef mte_sdr_h
#define mte_sdr_h

#ifndef mte_base_h
#include "mte_base.h"
#endif

/* TODO: header description
*/
#ifdef __cplusplus
extern "C"
{
#endif



/******************************************************************************
 * The mte_sdr_get_random() callback function                                 *
 *                                                                            *
 * Use of this function is mandatory to provide a crypographically safe       *
 * random number generator.                                                   *
 * The implementation must fill the given buff buffer with the required       *
 * number of bytes as given in bytes.                                         *
 ******************************************************************************/
typedef void(*mte_sdr_get_random)(void *context, void *buff, MTE_SIZE_T bytes);

/******************************************************************************/
/* Returns the encoder state size. Returns 0 if it fails (internal error).    */
/******************************************************************************/
MTE_SHARED
MTE_SIZE_T mte_sdr_enc_state_bytes(void);

/******************************************************************************
 * Returns the decoder state size. Returns 0 if it fails (internal error).    *
 ******************************************************************************/
MTE_SHARED
MTE_SIZE_T mte_sdr_dec_state_bytes(void);

/******************************************************************************
 * Returns the encode buffer size in bytes given the data length in bytes.    *
 * The encode buffer provided to mte_sdr_encrypt() must be of at least this   *
 * length.                                                                    *
 ******************************************************************************/
MTE_SHARED
MTE_SIZE_T mte_sdr_enc_buff_bytes(MTE_HANDLE state, MTE_SIZE_T data_bytes);

/******************************************************************************
 * Returns the decode buffer size in bytes given the encoded length in        *
 * bytes. Returns 0 if the input is invalid. The decode buffer provided to    *
 * mte_sdr_decrypt() must be of at least this length.                         *
 ******************************************************************************/
MTE_SHARED
MTE_SIZE_T mte_sdr_dec_buff_bytes(MTE_HANDLE state, MTE_SIZE_T data_bytes);

/******************************************************************************
 * Encrypt. Returns the status. The encrypted version is valid only if        *
 * mte_status_success is returned.                                            *
 *                                                                            *
 * The encoded buffer must be of sufficient length to hold the encoded        *
 * version. See mte_sdr_enc_buff_bytes(). Note that mte_sdr_enc_buff_bytes()  *
 * MUST be called before calling mte_sdr_encrypt().                           *
 *                                                                            *
 * A password must be provided. The minimum accepted length is 8 bytes.       *
 * No byte values are allowed to occur more than twice in the password.       *
 * If a GUID string is used, the rule about "no byte value more than twice"   *
 * does not apply.                                                            *
 * A callback function to supply cryptographically secure random data must be *
 * provided. See the mte_sdr_get_random typedef.                              *
 ******************************************************************************/
MTE_SHARED
mte_status mte_sdr_encrypt(MTE_HANDLE state, const void *data,
                           MTE_SIZE_T *bytes, void *encoded,
                           const void *password, MTE_SIZE_T password_bytes,
                           mte_sdr_get_random rnd_cb, void *context);

/******************************************************************************
 * Decrypt. Returns the status. The decrypted version is valid only if        *
 * mte_status_success is returned.                                            *
 *                                                                            *
 * The decoded buffer must be of sufficient length to hold the decoded        *
 * version. See mte_sdr_dec_buff_bytes(). Note that mte_sdr_dec_buff_bytes()  *
 * MUST be called before calling mte_sdr_decrypt().                           *
 *                                                                            *
 * A password must be provided. The minimum accepted length is 8 bytes.       *
 * No byte values are allowed to occur more than twice in the password.       *
 * If a GUID string is used, the rule about "no byte value more than twice"   *
 * does not apply.                                                            *
 ******************************************************************************/
MTE_SHARED
mte_status mte_sdr_decrypt(MTE_HANDLE state, const void *encoded,
                           MTE_SIZE_T *bytes, void *decoded, MTE_UINT8_T *off,
                           const void *password, MTE_SIZE_T password_bytes);

#ifdef __cplusplus
}
#endif

#endif


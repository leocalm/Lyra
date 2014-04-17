/**
 * Header file for the Lyra Password Hashing Scheme (PHS).
 * 
 * Author: The Lyra PHC team (http://www.lyra-kdf.net/).
 * 
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef LYRA_H_
#define LYRA_H_

typedef unsigned char byte ;

#ifndef N_COLS
#define N_COLS 64                                       //Number of columns in the memory matrix: fixed to 64 by default
#endif

#define ROW_LEN_INT64 (BLOCK_LEN_INT64 * N_COLS)        //Total length of a row: N_COLS blocks
#define ROW_LEN_BYTES (ROW_LEN_INT64 * 8)               //Number of bytes per row


int lyra(unsigned char *K, int kLen, const unsigned char *pwd, int pwdlen, const unsigned char *salt, int saltlen, int timeCost, int nRows, int nCols);

#endif /* LYRA_H_ */

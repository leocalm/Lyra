/**
 * Implementation of the Lyra2 Password Hashing Scheme (PHS).
 *
 * Author: The Lyra PHC team (http://www.lyra2.net/) -- 2015.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "Lyra2.h"
#include "Sponge.h"

/**
 * Executes Lyra2 based on the G function from Blake2b or BlaMka. The number of columns of the memory matrix is set to nCols = 256.
 * This version supports salts and passwords whose combined length is smaller than the size of the memory matrix,
 * (i.e., (nRows x nCols x b) bits, where "b" is the underlying sponge's bitrate). In this implementation, the "params"
 * is composed by all integer parameters (treated as type "unsigned int") in the order they are provided, plus the value
 * of nCols, (i.e., params = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
 * In case of parallel version, there are two more "params": total of threads and thread number (nPARALLEL || threadNumber).
 *
 * @param out The derived key to be output by the algorithm
 * @param outlen Desired key length
 * @param in User password
 * @param inlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param t_cost Parameter to determine the processing time (T)
 * @param m_cost Memory cost parameter (defines the number of rows of the memory matrix, R)
 *
 * @return 0 if the key is generated correctly; -1 or -2 if there is an error (usually due to lack of memory for allocation)
 */
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost) {
    return LYRA2(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost, N_COLS);
}


#if (nPARALLEL == 1)
/**
 * Executes Lyra2 based on the G function from Blake2b or BlaMka. This version supports salts and passwords
 * whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits,
 * where "b" is the underlying sponge's bitrate). In this implementation, the "params" is composed by all
 * integer parameters (treated as type "unsigned int") in the order they are provided, plus the value
 * of nCols, (i.e., params = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
 *
 * @param K The derived key to be output by the algorithm
 * @param kLen Desired key length
 * @param pwd User password
 * @param pwdlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param timeCost Parameter to determine the processing time (T)
 * @param nRows Number or rows of the memory matrix (R)
 * @param nCols Number of columns of the memory matrix (C)
 *
 * @return 0 if the key is generated correctly; -1 or -2 if there is an error (usually due to lack of memory for allocation)
 */
int LYRA2(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols) {
    //============================= Basic variables ============================//
    cudaError_t errorCUDA;
    //==========================================================================/
    uint gridSize, blockSize;
    gridSize = 1; //Number of blocks used in GPU execution
    blockSize = nPARALLEL; //Number of threads inside a block

    //Checks whether or not the salt+password are within the accepted limits
    if (pwdlen + saltlen > ROW_LEN_BYTES) {
        return -1;
    }

    //========== Initializing the Memory Matrix and Keys =============//

    // GPU memory matrix alloc:
    // Memory matrix: nRows of nCols blocks, each block having BLOCK_LEN_INT64 64-bit words
    uint64_t *memMatrixGPU;
    errorCUDA = cudaMalloc((void**) &memMatrixGPU, nRows * ROW_LEN_BYTES);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //keys on GPU
    unsigned char *pkeysGPU;
    errorCUDA = cudaMalloc((void**) &pkeysGPU, nPARALLEL * kLen * sizeof (unsigned char));
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Sponge state: 16 uint64_t, BLOCK_LEN_INT128 words of them for the bitrate (b) and the remainder for the capacity (c)
    uint64_t *stateThreadGPU;
    errorCUDA = cudaMalloc((void**) &stateThreadGPU, nPARALLEL * STATESIZE_BYTES);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Allocates the State Index to be absorbed by each thread.
    uint64_t *stateIdxGPU;
    errorCUDA = cudaMalloc((void**) &stateIdxGPU, nPARALLEL * BLOCK_LEN_BLAKE2_SAFE_BYTES);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Allocates the Password in GPU.
    unsigned char *pwdGPU;
    errorCUDA = cudaMalloc((void**) &pwdGPU, pwdlen);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // Transfers the password to GPU.
    errorCUDA = cudaMemcpy(pwdGPU, pwd, pwdlen, cudaMemcpyHostToDevice);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Allocates the Salt in GPU.
    unsigned char *saltGPU;
    errorCUDA = cudaMalloc((void**) &saltGPU, saltlen);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // Transfers the salt to GPU.
    errorCUDA = cudaMemcpy(saltGPU, salt, saltlen, cudaMemcpyHostToDevice);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }


    //========================== BootStrapping Phase ==========================//
    bootStrapGPU_P1 <<<gridSize, blockSize, nPARALLEL * STATESIZE_BYTES>>>(memMatrixGPU, pkeysGPU, kLen, pwdGPU, pwdlen, saltGPU, saltlen, timeCost, nRows, nCols, stateThreadGPU, stateIdxGPU);

    // Needs to wait all threads:
    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //============================ Setup, Wandering Phase and Wrap-up =============================//
    //================================ Setup Phase ==================================//
    //==Initializes a (nRows x nCols) memory matrix, it's cells having b bits each)==//
    //============================ Wandering Phase =============================//
    //=====Iteratively overwrites pseudorandom cells of the memory matrix=======//
    //============================ Wrap-up Phase ===============================//
    //========================= Output computation =============================//
    //Absorbs one last block of the memory matrix with the full-round sponge
    setupPhaseWanderingGPU_P1 <<<gridSize, blockSize, nPARALLEL * STATESIZE_BYTES>>>(memMatrixGPU, stateThreadGPU, timeCost, pkeysGPU, kLen, nRows);

    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error after Setup: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // Getting the keys back.
    errorCUDA = cudaMemcpy(K, pkeysGPU, kLen * sizeof (unsigned char), cudaMemcpyDeviceToHost);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        //printf( "Error number: %d \n", errorCUDA );
        return -2;
    }

    //Wiping out the GPU's internal Keys before freeing it
    cudaMemset(pkeysGPU, 0, nPARALLEL * kLen * sizeof (unsigned char));
    if (cudaSuccess != cudaGetLastError()) {
        printf("CUDA memory setting error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(cudaGetLastError()));
        return -2;
    }

    //========================= Freeing the memory =============================//
    cudaFree(memMatrixGPU);
    cudaFree(pkeysGPU);
    cudaFree(stateThreadGPU);
    cudaFree(stateIdxGPU);
    cudaFree(saltGPU);
    cudaFree(pwdGPU);
    //==========================================================================/
    return 0;
}
#endif  // nPARALLEL == 1

#if (nPARALLEL > 1)
/**
 * Executes Lyra2 based on the G function from Blake2b or BlaMka. This version supports salts and passwords
 * whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits,
 * where "b" is the underlying sponge's bitrate). In this implementation, the "params" is composed by all
 * integer parameters (treated as type "unsigned int") in the order they are provided, plus the value
 * of nCols, (i.e., params = kLen || pwdlen || saltlen || timeCost || nRows || nCols || nPARALLEL || threadNumber).
 *
 * @param K The derived key to be output by the algorithm
 * @param kLen Desired key length
 * @param pwd User password
 * @param pwdlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param timeCost Parameter to determine the processing time (T)
 * @param nRows Number or rows of the memory matrix (R)
 * @param nCols Number of columns of the memory matrix (C)
 *
 * @return 0 if the key is generated correctly; -1 or -2 if there is an error (usually due to lack of memory for allocation)
 */
int LYRA2(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols) {
    //============================= Basic variables ============================//
    int64_t i, j; //auxiliary iteration counter
    cudaError_t errorCUDA;
    uint64_t sizeSlice = nRows / nPARALLEL;

    //==========================================================================/
    uint gridSize, blockSize;
    gridSize = 1;
    blockSize = nPARALLEL;

    //Checks whether or not the salt+password are within the accepted limits
    if (pwdlen + saltlen > ROW_LEN_BYTES) {
        return -1;
    }

    //========== Initializing the Memory Matrix and Keys =============//

    //Allocates the keys
    unsigned char *pKeys = (unsigned char *) malloc(nPARALLEL * kLen * sizeof (unsigned char));
    if (pKeys == NULL) {
        return -1;
    }

    // GPU memory matrix alloc:
    // Memory matrix: nRows of nCols blocks, each block having BLOCK_LEN_INT64 64-bit words
    uint64_t *memMatrixGPU;
    errorCUDA = cudaMalloc((void**) &memMatrixGPU, nRows * ROW_LEN_BYTES);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //keys on GPU
    unsigned char *pkeysGPU;
    errorCUDA = cudaMalloc((void**) &pkeysGPU, nPARALLEL * kLen * sizeof (unsigned char));
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Sponge state: 16 uint64_t, BLOCK_LEN_INT128 words of them for the bitrate (b) and the remainder for the capacity (c)
    uint64_t *stateThreadGPU;
    errorCUDA = cudaMalloc((void**) &stateThreadGPU, nPARALLEL * STATESIZE_BYTES);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Allocates the State Index to be absorbed by each thread.
    uint64_t *stateIdxGPU;
    errorCUDA = cudaMalloc((void**) &stateIdxGPU, nPARALLEL * BLOCK_LEN_BLAKE2_SAFE_BYTES);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Allocates the Password in GPU.
    unsigned char *pwdGPU;
    errorCUDA = cudaMalloc((void**) &pwdGPU, pwdlen);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // Transfers the password to GPU.
    errorCUDA = cudaMemcpy(pwdGPU, pwd, pwdlen, cudaMemcpyHostToDevice);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //Allocates the Salt in GPU.
    unsigned char *saltGPU;
    errorCUDA = cudaMalloc((void**) &saltGPU, saltlen);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // Transfers the salt to GPU.
    errorCUDA = cudaMemcpy(saltGPU, salt, saltlen, cudaMemcpyHostToDevice);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }


    //========================== BootStrapping Phase ==========================//
    bootStrapGPU <<<gridSize, blockSize, nPARALLEL * STATESIZE_BYTES>>>(memMatrixGPU, pkeysGPU, kLen, pwdGPU, pwdlen, saltGPU, saltlen, timeCost, nRows, nCols, stateThreadGPU, stateIdxGPU);

    // Needs to wait all threads:
    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    //============================ Setup, Wandering Phase and Wrap-up =============================//
    //================================ Setup Phase ==================================//
    //==Initializes a (nRows x nCols) memory matrix, it's cells having b bits each)==//
    //============================ Wandering Phase =============================//
    //=====Iteratively overwrites pseudorandom cells of the memory matrix=======//
    //============================ Wrap-up Phase ===============================//
    //========================= Output computation =============================//
    //Absorbs one last block of the memory matrix with the full-round sponge
    setupPhaseWanderingGPU <<<gridSize, blockSize, nPARALLEL * STATESIZE_BYTES>>>(memMatrixGPU, stateThreadGPU, sizeSlice, timeCost, pkeysGPU, kLen);

    cudaThreadSynchronize();

    errorCUDA = cudaGetLastError();
    if (cudaSuccess != errorCUDA) {
        printf("CUDA kernel call error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error after Setup: %s \n", cudaGetErrorString(errorCUDA));
        return -2;
    }

    // Getting the keys back.
    errorCUDA = cudaMemcpy(pKeys, pkeysGPU, nPARALLEL * kLen * sizeof (unsigned char), cudaMemcpyDeviceToHost);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
        //printf( "Error number: %d \n", errorCUDA );
        return -2;
    }

    //Wiping out the GPU's internal Keys before freeing it
    cudaMemset(pkeysGPU, 0, nPARALLEL * kLen * sizeof (unsigned char));
    if (cudaSuccess != cudaGetLastError()) {
        printf("CUDA memory setting error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(cudaGetLastError()));
        return -2;
    }

    // XORs all Keys
    for (i = 1; i < nPARALLEL; i++) {
        for (j = 0; j < kLen; j++) {
            pKeys[j] ^= pKeys[i * kLen + j];
        }
    }

    // Returns in the correct variable
    memcpy(K, pKeys, kLen);

    //Wiping out the CPU's Keys before freeing it
    memset(pKeys, 0, nPARALLEL * kLen * sizeof (unsigned char));

    //========================= Freeing the memory =============================//
    cudaFree(memMatrixGPU);
    cudaFree(pkeysGPU);
    cudaFree(stateThreadGPU);
    cudaFree(stateIdxGPU);
    cudaFree(saltGPU);
    cudaFree(pwdGPU);

    //Free allKeys
    free(pKeys);
    pKeys = NULL;
    //==========================================================================/
    return 0;
}

#endif
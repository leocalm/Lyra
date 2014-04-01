#ifndef LYRA_H_
#define LYRA_H_

typedef unsigned char byte ;

#define SALT_LEN_INT64 2                                //Salts must have 128 bits (=16 bytes, =2 uint64_t)
#define SALT_LEN_BYTES (SALT_LEN_INT64 * 8)             //Salt length, in bytes

#define BLOCK_LEN_INT64 8                               //Block lenght: 512 bits (=64 bytes, =8 uint64_t)
#define BLOCK_LEN_BYTES (BLOCK_LEN_INT64 * 8)           //Block lenght, in bytes

#define N_COLS 64                                       //Number of columns in the memory matrix: fixed to 64

#define ROW_LEN_INT64 (BLOCK_LEN_INT64 * N_COLS)        //Total length of a row: 64 blocks, or 512 uint64_t
#define ROW_LEN_BYTES (ROW_LEN_INT64 * 8)               //Number of bytes per row: 512 * 8


int lyra(const unsigned char *pwd, int pwdSize, const unsigned char *salt, int timeCost, int nRows, int kLen, unsigned char *K);

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

#endif /* LYRA_H_ */

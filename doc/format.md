
Passmate uses the scrypt encrypted data format for encrypting the JSON data on disk.

This scrypt-encrypted file is stored in the following locations:

* Linux: $HOME/.pmate
* Mac OS X: ???
* Windows: ???

Original description of the format in the scrypt source code: https://github.com/Tarsnap/scrypt/blob/master/FORMAT

scrypt encrypted data format
----------------------------

| offset | length (bytes) | content |
| ------ | ------ | ------- |
| 0	     | 6      |	"scrypt" |
| 6	     | 1	  | scrypt data file version number (== 0) |
| 7	     | 1	  | log2(N) (must be between 1 and 63 inclusive) |
| 8	     | 4	  | r (big-endian integer; must satisfy r * p < 2^30) |
| 12	 | 4	  | p (big-endian integer; must satisfy r * p < 2^30) |
| 16	 | 32	  | salt |
| 48	 | 16	  | first 16 bytes of SHA256(bytes 0 .. 47) |
| 64	 | 32	  | HMAC-SHA256(bytes 0 .. 63) |
| 96	 | X	  | data xor AES256-CTR key stream generated with nonce == 0 |
| 96+X	 | 32	  | HMAC-SHA256(bytes 0 .. 96 + (X - 1)) |


The lower 256 bits of the scrypt result is used as key for AES256-CTR encryption, the upper 256 bits as key for HMAC-SHA256.

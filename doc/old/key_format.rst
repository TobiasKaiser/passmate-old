Passmate key format
-------------------

42 bytes, separated to 14 dash-separated byte triplets in hexadecimal notation:

aaaaaa-aaaaaa-aaaakk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkcccc
972833-867473-888541-975566-332200-641368-206880-972833-867473-888541-975566-332200-641368-206880

| offset | length (bytes) | name | description |
| ------ | -------------- | ---- | ----------- |
| 0		 | 8              | a    | account number |
| 8	     | 32             | k    | key |
| 40     | 2              | c    | crc16 checksum |


## Derived keys

The 256 bit key is used to derive the key for the btoken's AES256-CBC encryption, the key for the btoken's SHA256-HMAC message digest and the auth token, which is used for authenticating with the sync server.

They are derived by computing the SHA256-HMAC message digests of the strings "aes_data_key", "mac_key" and "auth_token".
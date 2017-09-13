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

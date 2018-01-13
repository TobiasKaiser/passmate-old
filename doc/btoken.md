Passmate b-token
----------------

<strike>The JSON storage data, but only the first part of the array, not the second one which is the config part, is encrypted in the scrypt format, and then encrypted again</strike> The JSON storage data, but only the first part of the array, not the second one which is the config part, is space-padded and encrypted using AES-CBC using a key derived from the sync key. Together with a HMAC message digest and the random IV, this data is called b-token and is transferred to the server and stored there. 

See key_format.md how the SHA256-HMAC and AES256-CBC keys are derived from the sync key.

b-token format:

| offset | length (bytes) | content |
| ------ | -------------- | ------- |
| 0		 | 16             | IV for AES256-CBC |
| 16     | 32			  | SHA256-HMAC of ciphertext |
| 48     | X (inferred from btoken length) | ciphertext in AES256-CBC |

The b-tokens are stored by the server prepended by a 32 byte auth key, which is also derived from the sync key.
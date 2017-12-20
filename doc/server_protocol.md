Passmate Client / server protocol
---------------------------------

Connect via TCP port 29556 (from ASCII 'st') through TLS.

| direction 	   | length (bytes) | content |
| ---------------- | -------------- | ------- |   
| client -> server | 24 			| "passmate-server-protocol" |
| server -> client | 24 			| "passmate-protocol-server" |
| server -> client | 4 				| banner length B (uint32_t in big endian) |
| server -> client | B 				| server banner |
| client -> server | 1 				| Requested action. 'c' to create, 'u' for update, 'r' for reset |
|                  |                | ... |

See the following sections create, update, reset for what follows depending on the requested action byte.

## Create

Through the create action the client requests to store a new btoken on the server. The server sends back an account number which can be used subsequently by the client to update the btoken.

| direction        | length (bytes) | content |
| ---------------- | -------------- | ------- |   
|                  |                | ...|
| client -> server | 32             | auth token |
| client -> server | 4              | btoken length Ls (uint32_t in big endian) |
| client -> server | Ls             | btoken to be stored on server |
| server -> client | 8              | new account no. (8 byte random string) |
| server -> client |                | server closes connection |

## Update

Through the update action the client requests to update his btoken on the server to be updated. The btokens on the server are identified by an existing account number. An update always consists of the server sending the existing btoken and then receiving the new btoken. The client will typically merge the received btoken and send the btoken after the merge with its local database back to the server.

| direction        | length (bytes) | content |
| ---------------- | -------------- | ------- |   
|                  |                | ...|
| client -> server | 8              | account no. |
| client -> server | 32             | auth token |
| server -> client | 4              | btoken length Lr (uint32_t in big endian) |
| server -> client | Lr             | btoken currently stored on server |
| server -> client | 4              | btoken length Ls (uint32_t in big endian) |
| client -> server | Ls             | btoken to be stored on server |
| client -> server | 8              | account no. (8 byte random string) |
| server -> client |                | server closes connection |


## Reset

Through the reset action the client requests the btoken stored on the server to be deleted.

| direction        | length (bytes) | content |
| ---------------- | -------------- | ------- |   
|                  |                | ...|
| client -> server | 8              | account no. |
| client -> server | 32             | auth token |
| server -> client |                | server closes connection |
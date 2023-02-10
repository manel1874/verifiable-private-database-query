# Verifiable private database query in MP-SPDZ

Private database query is a crucial issue in the field of secure multiparty computation (MPC). The goal of this problem is to allow a client (C) to query a database owner (DB) while keeping the client's query confidential and ensuring that the client only receives relevant information related to the query.

While MPC typically provides a secure environment for all parties to input data without verifying the authenticity of the input, there are scenarios [1] where it is important to confirm the accuracy of the input data, especially in situations where the veracity of the data is crucial.

This tutorial will guide you through the process of implementing a verifiable private database query using the MP-SPDZ framework. We will begin by introducing the general protocol and then proceed to walk you through a step-by-step implementation guide. By the end of this tutorial, you will have a solid understanding of how to use the MP-SPDZ framework to perform secure, verifiable database queries.


## Security requirements and protocol description

In this tutorial, we will explore a scenario involving three entities: a Client (C), a Database owner (DB), and Blockchain nodes (N).

The database owned by DB is integrated with a blockchain managed by several nodes (N). Each row of the database is hashed and its hash value is recorded on the blockchain, along with a unique row identifier.

The security requirements for this scenario can be summarized as follows:

For the Client (C):
- Confidentiality of the query: The Client should be able to query the database without revealing which field he is querying.
- Verification of data integrity: The Client should be able to confirm that the answers received from the database are not manipulated by the Database owner.

For the Database owner (DB):
- Data privacy: The Database owner should only provide information related to the query to the Client.

For the Blockchain nodes (N):
- Immutable database entries: The Blockchain nodes should ensure the integrity of the database entries, preventing corruption of the data.


The protocol between C, DB and N is as follows:

1. C and DB engage in an MPC protocol where C inputs `Query = (row_id, column_id)` and DB inputs some `Table`. The MPC engine outputs `None` to DB and `Answer = (value, hash)`, where `value = Table[row_id][column_id]` and `hash = SHA256(Table[row_id])`.

2. C and N engage in an MPC protocol where C inputs `Verify = (row_id, hash)` and N inputs the corresponding `BCTable`. The MPC engine outputs `None` to N and `Validity` (`true` or `false`) to C, where `Validity = ( hash == BCTable[row_id][1] )` for `BCTable[row_id][1]` to be the hash value entry of the database corresponding to row `row_id`-th of `Table`.

Step 1 ensures confidentiality of the query and data privacy security requirements. Step 2 ensuresverification of data integrity and immutable database entries security requirements.


## Implementation details

To implement the solution using the MP-SPDZ framework, it is necessary to preprocess all inputs to ensure they are in the correct format. The preprocessing phase involves using the Rust programming language to translate `.csv` files into the `Input-P0-0 type file.

### Preprocessing

The MP-SPDZ framework only accepts signed or unsigned numbers as inputs, so the values in the database fields need to be encoded into numbers. We will assume that each field is a 10-byte string encoded in UTF-8 format. The hashing procedure inside the MPC engine uses the SHA256 circuit provided [here](https://homes.esat.kuleuven.be/~nsmart/MPC/), but it requires well-formatted inputs with proper padding. The database owner can perform the preprocessing steps, which include the following:

1. Encoding the 10-byte strings into UTF-8 encoding and separating each byte with a space to allow the MP-SPDZ framework to differentiate between elements.

2. Executing the padding procedure for each line to ensure proper formatting of the inputs.

By following these preprocessing steps, the database owner can ensure that the inputs are in the correct format and ready to be used with the MP-SPDZ framework.

#### Implementation

The `./target/debug/preprocessing` executable built from [`main.rs`](https://github.com/manel1874/verifiable-private-database-query/blob/main/preprocessing/src/main.rs) accepts a `file.csv` file saved in the main folder (`preprocessing`) and creates a new file called `pre_file.txt` in the same folder.

Example:

`file.csv`
```
aaaaaaaaaa,aaaaaaaaaa,aaaaaaaaaa,aaaaaaaaaa,aaaaaaaaaa
```

`pre_file.txt`
```
97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 128 0 0 0 0 0 0 0 0 0 0 0 1 144
```

### C queries DB (Step 1)





### C queries N (Step 2)




## References

[1] [Catching MPC Cheaters: Identification and Openability](https://eprint.iacr.org/2016/611.pdf)

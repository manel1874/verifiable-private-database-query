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

We start by importing some of the elements used by the compiler to generate an appropriate circuit for our use-case.

```python
1	########################
2
3	#       Imports        #
4
5	########################
6
7
8	from circuit import Circuit
9	from util import if_else, bit_compose
```

`Circuit`: it contains the boolean circuit used to compute SHA256.

`if_else`: MP-SPDZ framework do not accept if statements under secret values because branching is not accepted by the security model of MPC. To circunvent this constraint for simple (singular) elements, MP-SPDZ accepts the following `if_else` function:
```
if_else(cond, a, b) = cond * (a - b) + b
```
where all `cond`, `a` and `b` elements can be private.

`bit_compose`: Receives a list/array of bits and compose it into a number of a defined type (e.g. `sint`, `sbitint`).

Example:

```python
from util import bit_compose

si8 = sbitint.get_type(8)
num_0100110 = si8(38)

bits = num_0100110.bit_decompose()                  # bits = [0, 1, 1, 0, 0, 1, 0]

# bit_compose compose `bits` in reversed order
res = si8.bit_compose(bits)     					# res = 0100110 = 38


for k in range(8):
    print_ln("bits %s-th element = %s", k, bits[k].reveal())

print_ln("res = %s", res.reveal())
```

Output:
```python
>>>		bits 0-th element = 0
>>>		bits 1-th element = 1
>>>		bits 2-th element = 1
>>>		bits 3-th element = 0
>>>		bits 4-th element = 0
>>>		bits 5-th element = 1
>>>		bits 6-th element = 0
>>>		bits 7-th element = 0
>>>		res = 38
>>>		The following timing is inclusive preprocessing.
>>>		Time = 0.00514026 seconds 
>>>		Data sent = 0.02512 MB in ~24 rounds (party 0)
>>>		Global data sent = 0.050256 MB (all parties)
```

To execute the first step of the protocol, we need two auxiliar function: `concatenate_to_hash` and `compute_tbl_entry_sha256`. `concatenate_to_hash` concatenates the input line from the DB table (`Array` of `sbits`) into one 512-bit element of type `sbits`. 


```python
################################

#        Functions def         #

################################


def concatenate_to_hash(tbl_l):
    """ Concatenate an 'Array' of 'sbits'.

    Note: we assume the following parameters (hardcoded)
        lenght of tbl_l = 64
        length of sbits = 8 (in the implementation we use sb9 
                             as the system considers signed
                             numbers)
    
    :param tbl_l: Array of sbits.

    :output: A 512-`sbits` element."""

    # Step 1: initialization
    sb512 = sbits.get_type(512)
    bits_l = []

    # Step 2: concatenate the bit decoposition of all individual 
    # elements from tbl_l
    for i in range(0, 64):
        # Concatenate in reversed order
        val = tbl_l[63-i] 
        bits_l += val.bit_decompose()[:8]

    return sb512.bit_compose(bits_l)


def compute_tbl_entry_sha256(secret):
    """ Compute the SHA256 of secret
    
    :param secret: a preprocessed element to be hashed (svi512)
                    Preprocess: padding step.
    """
    
    # Step 1: import sha256 circuit
    sha256 = Circuit('sha256')

    # Step 2: initialize state variable 
    siv256 = sbitintvec.get_type(256)
    state = siv256(0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19)

    # Step 3: run circuit
    result = sha256(secret, state)
    res = result.elements()[0]

    # Step 4: parse res as four 64-bit sint 
    trunc_64_0 = res.TruncPr(64,0)
    trunc_128_64 = res.TruncPr(128,64)
    trunc_192_128 = res.TruncPr(192,128)
    trunc_256_192 = res.TruncPr(256,192)

    sint_trunc_64_0 = sint.bit_compose(sint(trunc_64_0))
    sint_trunc_128_64 = sint.bit_compose(sint(trunc_128_64))
    sint_trunc_192_128 = sint.bit_compose(sint(trunc_192_128))
    sint_trunc_256_192 = sint.bit_compose(sint(trunc_256_192))

    # Step 5: save truncated result to array
    hash_array = Array(4, sint)
    hash_array[0] = sint_trunc_64_0
    hash_array[1] = sint_trunc_128_64
    hash_array[2] = sint_trunc_192_128
    hash_array[3] = sint_trunc_256_192

    return hash_array
```



### C queries N (Step 2)




## References

[1] [Catching MPC Cheaters: Identification and Openability](https://eprint.iacr.org/2016/611.pdf)

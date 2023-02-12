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

### Step 1: cliente queries database owner 

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

`bit_compose`: Receives a list/array of bits and composes it into a number of some defined type (e.g. `sint`, `sbitint`).

Example 1:

```python
from util import bit_compose

si8 = sbitint.get_type(8)
num_0100110 = si8(38)

bits = num_0100110.bit_decompose()					# bits = [0, 1, 1, 0, 0, 1, 0]

# bit_compose compose `bits` in reversed order
res = si8.bit_compose(bits)							# res = 0100110 = 38


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

To execute the first step of the protocol, we need two auxiliar function: `concatenate_to_hash` and `compute_tbl_entry_sha256`.


```python
12		################################
13
14		#        Functions def         #
15
16		################################
17
18
19		def concatenate_to_hash(tbl_l):
20		    """ Concatenate an 'Array' of 'sbits'.
21
22		    Note: we assume the following parameters (hardcoded)
23		        lenght of tbl_l = 64
24		        length of sbits = 8 (in the implementation we use sb9 
25		                             as the system considers signed
26		                             numbers)
27		    
28		    :param tbl_l: Array of sbits.
29
30		    :output: A 512-`sbits` element."""
31
32		    # Step 1: initialization
33		    sb512 = sbits.get_type(512)
34		    bits_l = []
35
36		    # Step 2: concatenate the bit decoposition of all individual 
37		    # elements from tbl_l
38		    for i in range(0, 64):
39		        # Concatenate in reversed order
40		        val = tbl_l[63-i] 
41		        bits_l += val.bit_decompose()[:8]
42
43		    return sb512.bit_compose(bits_l)
```


`concatenate_to_hash` concatenates one line from the DB table (`Array of `sbits`) into one 512-bit element of type `sbits`. We use the following elements in the function definition:

- `sb512`: `sbits` with size 512 bits to save one line.
- `bits_l`: list of bits that will be used by `bit_compose` to build a `sb512` type number from this list of numbers. Recall from `Example 1` that `bit_compose` composes in reversed order, i.e. `bits_l[0]` is the least significant bit of the returned value. Therefore, `bits_l` has to be built in reversed order (check lines 38-41).

Example 2:

For `tbl_l = [96, ..., 97, 98, 99]. `concatenate_to_hash(tbl_l) = 01100000...011000010110001001100011` 


```python
46		def compute_tbl_entry_sha256(secret):
47		    """ Compute the SHA256 of secret
48		    
49		    :param secret: a preprocessed element to be hashed (svi512)
50		                    Preprocess: padding step.
51		    """
52		    
53		    # Step 1: import sha256 circuit
54		    sha256 = Circuit('sha256')
55
56		    # Step 2: initialize state variable 
57		    siv256 = sbitintvec.get_type(256)
58		    state = siv256(0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19)
59
60		    # Step 3: run circuit
61		    result = sha256(secret, state)
62		    res = result.elements()[0]
63
64		    # Step 4: parse res as four 64-bit sint 
65		    trunc_64_0 = res.TruncPr(64,0)
66		    trunc_128_64 = res.TruncPr(128,64)
67		    trunc_192_128 = res.TruncPr(192,128)
68		    trunc_256_192 = res.TruncPr(256,192)
69
70		    sint_trunc_64_0 = sint.bit_compose(sint(trunc_64_0))
71		    sint_trunc_128_64 = sint.bit_compose(sint(trunc_128_64))
72		    sint_trunc_192_128 = sint.bit_compose(sint(trunc_192_128))
73		    sint_trunc_256_192 = sint.bit_compose(sint(trunc_256_192))
74
75		    # Step 5: save truncated result to array
76		    hash_array = Array(4, sint)
77		    hash_array[0] = sint_trunc_64_0
78		    hash_array[1] = sint_trunc_128_64
79		    hash_array[2] = sint_trunc_192_128
80		    hash_array[3] = sint_trunc_256_192
81
82		    return hash_array
```
 
 `compute_tbl_entry_sha256` computes the SHA256 of some padded `secret`. It outputs an array with the output of SHA256(secret) split in four 64-bit numbers. 

 Note: lines 70-73 are used to convert `sbitint` type to `sint` (check this [issue 372](https://github.com/data61/MP-SPDZ/issues/372)).

 ```python
87		########################
88
89		#        Input         #
90
91		########################
92
93		# Initizalize hardcoded parameters
94		len_of_entry = 10      # Length of each entry (bytes)
95		n_of_columns = 5       # Number of columns
96		n_of_lines = 10        # Number of lines
97
98
99		###                  Party 0                   ###
100
101		user_input_id = sint.get_input_from(0)
102		user_input_column = sint.get_input_from(0)
103
104
105
106		###--------------------------------------------###
107
108
109		###                  Party 1                   ###
110
111		sb9 = sbits.get_type(9)
112		sb512 = sbits.get_type(512)
113
114		tbl = Matrix(n_of_lines, 64, sb9)
115
116		for i in range(0, n_of_lines):
117		    tbl[i].input_from(1)
118
119		###--------------------------------------------###
 ```

Above, we take the secret inputs of Party 0 (client) and Party 1 (database owner). 

- Party 0: inputs the line number (`user_input_id`) and the column number (`user_input_column`).
- Party 1: inputs a table with 64 columns (each entry is a 8-bit element)

Note: currently, the program has some hardcoded parameters such as the bit length of each entry (`len_of_entry`), the number of columns dedicated to data (`n_of_columns`) and the number of lines (`n_of_lines`).


```python
123		################################
124
125		#        Search & Hash         #
126
127		################################
128
129
130		# Initialize types
131		siv512 = sbitintvec.get_type(512)    
132
133
134		# Initialize tmp variables
135		tmp_lfnd = sintbit(0)  # temporary register to save line found
136		fnl_lfnd = sintbit(0)  # final register to save line found
137
138		tmp_cfnd = sintbit(0)  # temporary register to save column found
139		fnl_cfnd = sintbit(0)  # final register to save column found
140
141
142		# Initialize outputs
143		output_hash = Array(4, sint)
144		output_query = Array(len_of_entry, sint)
145
146
147		for i in range(n_of_lines):
148		    
149		    tmp_lfnd = i == user_input_id
150		    fnl_lfnd = fnl_lfnd | tmp_lfnd
151
152		    # Compute hash of line i
153		    line_in_bits = concatenate_to_hash(tbl[i])
154		    secret_line_in_bits = siv512(line_in_bits)
155		    cmp_hash = compute_tbl_entry_sha256(secret_line_in_bits)
156
157		    for j in range(n_of_columns):
158
159		        tmp_cfnd = j == user_input_column
160		        fnl_cfnd = fnl_cfnd | tmp_cfnd
161
162		        match = tmp_cfnd & tmp_lfnd
163
164		        # Prepare output for query
165		        for k in range(len_of_entry):
166		            val = sint.bit_compose(sint(tbl[i][j*len_of_entry + k]))
167		            output_query[k] = if_else(match, val, output_query[k])
168
169		        # Prepare output for hash
170		        output_hash[0] = if_else(match, cmp_hash[0], output_hash[0])
171		        output_hash[1] = if_else(match, cmp_hash[1], output_hash[1])
172		        output_hash[2] = if_else(match, cmp_hash[2], output_hash[2])
173		        output_hash[3] = if_else(match, cmp_hash[3], output_hash[3])
```

Between lines 130-173 we have the main part of the first step of the protocol. For every line we compute the corresponding hash using the auxiliary functions `concatenate_to_hash` (line 153) and `compute_tbl_entry_sha256` (line 155). We save the hash of the desired line to `output_hash` array and the value of the desired entry to `output_query` array.

```python
################################

#         Print output         #

################################

for k in range(len_of_entry):
    print_ln_to(0, "The %s-th letter of the query output is the following: %s", k, output_query[k].reveal_to(0))

print_ln_to(0, "hash[0:64] = %s", output_hash[0].reveal_to(0))
print_ln_to(0, "hash[64:128] = %s", output_hash[1].reveal_to(0))
print_ln_to(0, "hash[128:192] = %s", output_hash[2].reveal_to(0))
print_ln_to(0, "hash[192:256] = %s", output_hash[3].reveal_to(0))
```
Finally, we print only to Party 0 (cliente) the result of the query (line 332) and the output of the desired hash (lines 334-337).



### Step 2: cliente queries blockchain

TODO




## References

[1] [Catching MPC Cheaters: Identification and Openability](https://eprint.iacr.org/2016/611.pdf)
import sys
from base64 import b64encode, b64decode
import tenseal as ts
from time import time
import socket
import pickle
from math import log2
from parameters import sigma_max, output_bits, plain_modulus, poly_modulus_degree, number_of_hashes, bin_capacity, alpha, ell, hash_seeds
from cuckoo_hash import Cuckoo
from auxiliary_functions import windowing
from oprf import order_of_generator, client_prf_online_parallel
import httpx

oprf_client_key = 12345678910111213141516171819222222222222

log_no_hashes = int(log2(number_of_hashes)) + 1
base = 2 ** ell
minibin_capacity = int(bin_capacity / alpha)
logB_ell = int(log2(minibin_capacity) / ell) + 1 # <= 2 ** HE.depth
dummy_msg_client = 2 ** (sigma_max - output_bits + log_no_hashes)

remote_host = sys.argv[1]
client = httpx.Client(base_url=remote_host, timeout=600)

# Setting the public and private contexts for the BFV Homorphic Encryption scheme
private_context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=poly_modulus_degree, plain_modulus=plain_modulus)
public_context = ts.context_from(private_context.serialize())
public_context.make_context_public()

# We prepare the partially OPRF processed database to be sent to the server
pickle_off = open("client_preprocessed", "rb")
encoded_client_set = pickle.load(pickle_off)
response = client.post("oprf", json={"points": encoded_client_set})
response.raise_for_status()

PRFed_encoded_client_set = response.json()["points"]
t0 = time()

# We finalize the OPRF processing by applying the inverse of the secret key, oprf_client_key
key_inverse = pow(oprf_client_key, -1, order_of_generator)
PRFed_client_set = client_prf_online_parallel(key_inverse, PRFed_encoded_client_set)
print(' * OPRF protocol done!')

# Each PRFed item from the client set is mapped to a Cuckoo hash table
CH = Cuckoo(hash_seeds)
for item in PRFed_client_set:
    CH.insert(item)

# We padd the Cuckoo vector with dummy messages
for i in range(CH.number_of_bins):
    if CH.data_structure[i] is None:
        CH.data_structure[i] = dummy_msg_client

# We apply the windowing procedure for each item from the Cuckoo structure
windowed_items = []
for item in CH.data_structure:
    windowed_items.append(windowing(item, minibin_capacity, plain_modulus))

plain_query = [None for k in range(len(windowed_items))]
enc_query = [[None for j in range(logB_ell)] for i in range(1, base)]

# We create the <<batched>> query to be sent to the server
# By our choice of parameters, number of bins = poly modulus degree (m/N =1), so we get (base - 1) * logB_ell ciphertexts
for j in range(logB_ell):
    for i in range(base - 1):
        if ((i + 1) * base ** j - 1 < minibin_capacity):
            for k in range(len(windowed_items)):
                plain_query[k] = windowed_items[k][i][j]
            enc_query[i][j] = b64encode(ts.bfv_vector(private_context, plain_query).serialize()).decode()

t1 = time()
print(" * Sending the context and ciphertext to the server....")
response = client.post("query", json={"public_context": b64encode(public_context.serialize()).decode(), "enc_query": enc_query})
if response.status_code != 200:
    print(response.json())
response.raise_for_status()
t2 = time()
# Here is the vector of decryptions of the answer
ciphertexts = [b64decode(ct) for ct in response.json()]
decryptions = [ts.bfv_vector_from(private_context, ct).decrypt() for ct in ciphertexts]

recover_CH_structure = []
for matrix in windowed_items:
    recover_CH_structure.append(matrix[0][0])

count = [0] * alpha

g = open('client_set', 'r')
client_set_entries = g.readlines()
g.close()

'''
This code has been modified to return only the count of the intersection
'''
count = 0
for j in range(alpha):
    for i in range(poly_modulus_degree):
        # If there is an index of this vector where he gets 0, then the (Cuckoo hashing) item corresponding to this index belongs to a minibin of the corresponding server's bin.
        if decryptions[j][i] == 0:
            count = count + 1

t3 = time()
print("Client Set Length: ", len(client_set_entries))
print("Intersection Set Length: ", count)
print("Disconnecting...\n")
print('  Client ONLINE computation time {:.2f}s'.format(t1 - t0 + t3 - t2))
print('  Communication size:')
#print('    ~ Client --> Server:  {:.2f} MB'.format((client_to_server_communiation_oprf + client_to_server_communiation_query )/ 2 ** 20))
#print('    ~ Server --> Client:  {:.2f} MB'.format((server_to_client_communication_oprf + server_to_client_query_response )/ 2 ** 20))

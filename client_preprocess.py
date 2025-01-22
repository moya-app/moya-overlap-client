import pickle
from oprf import client_prf_offline, order_of_generator, G
from time import time

# client's PRF secret key (a value from  range(order_of_generator))
oprf_client_key = 12345678910111213141516171819222222222222
t0 = time()

'''
Diffie-Hellman (DH), known as exponential key exchange, is a key exchange protocol that allows
sender and receiver to communicate over public channels by generating a unique session key for symmetric encryption.

Elliptic Curve Diffied-Hellman (ECDH) follows the same protocol as DH but uses algebraic curves in its key generation
as opposed to generating large numbers using integers modulo a prime number (finite field of p elements where integers mod p is a finite field and p is a prime number).
'''
# key * generator of elliptic curve
client_point_precomputed = (oprf_client_key % order_of_generator) * G

client_set = []
f = open('client_set', 'r')
lines = f.readlines()
for item in lines:
	client_set.append(int(item[:-1]))
f.close()

# OPRF layer: encode the client's set as elliptic curve points.
encoded_client_set = [client_prf_offline(item, client_point_precomputed) for item in client_set]

g = open('client_preprocessed', 'wb')
pickle.dump(encoded_client_set, g)	 
g.close()   
t1 = time()
print('Client OFFLINE time: {:.2f}s'.format(t1-t0))

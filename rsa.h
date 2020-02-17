#ifndef _SHA_H
#define _SHA_H

#define LIMIT 10000

typedef std::pair<int, int> PublicKey;
typedef std::pair<int, int> PrivateKey;
struct Keys {
    PublicKey public_key;
    PrivateKey private_key;
};

int log_power(int, int, int);
bool rabin_miller(int);
int generate_prime();
int gcd(int, int);
int generate_coprime(int);
std::pair<int, int> euclid_extended(int, int);
int modular_inverse(int, int);
Keys generate_keys();
int encrypt(PublicKey, int);
int decrypt(PrivateKey, int);

#endif

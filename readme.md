# go vault

Go vault is a personal project that aims to understand how does 1Password works under the hood by cloning esential features like end to end encryption and zero knowlege architecture.

The main idea is to create gRPC worker which is in charge to manage users vaults following the 1Password standards.

## 1Password main features

1. **True end to end encryption:** Every key and encryptions are made in the client devices.

2. **Zero knowlege:** All encryptions and decryptions are done by the user devices, and the server will never know the user password and secret keys.

3. **User control sharing:** Only the user who holds a vault key can share a vault.

## Registration steps

1. The user creates a memorable password.

2. The user device creates a secret key:
  - The 1P secret keys are created with a version `A3` the user id `BSWSIB` and a sequence of 26 random chosen characters `708CTYLIKD41C3D286TVMD45EC`, this secret key will look like this: `A3-BSWSIB-708CTY-LIKD4-1C3D2-86TVM-D45EC`. Hypens are added to make the key more readable but they are not part of the secret key.
  - This generated secret key is supposed to be storaged in the users devices.
  - In this project we will mimic that standard with the next format `A1-{user_id}-{secret[:6]}-{secret[6:11]}-{secret[11:16]}-{secret[16:21]}-{secret[21:26]}`.

3. Compute AUK
  1. Generate encryption key salt.
  2. Compute the Account Unlock Key (AUK) with 2SKD using the salt, user password and user secret key.

4. Create encrypted account key set:
  1. Generate private key and compute public key.
  2. Encrypt private key with AUK
  3. Generate key set UUID
  4. Include key set format

5. The must common methods used to authenticate the user is "offuscating" the user password with a Key Derivation Function (KDF), a Password Based KDF (PBKDF) or Memory-Hard Function (MHF) saving the offuscated password in the database. Every time someone wants to authenticate to the server it has to send its password to the server and then the password is compared with the offuscated password, if the comparation succeeded the server grants permission.

  This authentication methods are just enough safe, but there is a problem, we are breaking one of the main 1P features the **Zero knowledge** and that's because the user must have to send the password to the server.

  We can solve this by implementitg a Password Authentication Key Exchange (PAKE). By implementing this method the client and the server are able to send each other puzzles thah can only be solve by knowing the secret without transmitting any secrets. In each aunthentication the generated puzzles are different and unique. The PAKE method used by 1P is Secure Remote Password (SRP), but this method still breaknig the **Zero knowelge** rule, because the server stores a long-term verifier which is mathematically related to the user password. To solve this 1P adds an extra layer of security to prevent this by using a two-secret key derivation (2SKD) with the user password and the secret key, that way if an attacker steals that verifier they have no guess the user password and a 128-bit strong secret key.

  1. Generate authentication salt.
  2. Derive SRP-x from account password, account secret key and authentication salt.
  3. Compute SRP verifier from SRP-x

6. 1P generates a emergency kit just in case the user lose access to its account, this emergency kit contains the user secret key and an empty password field, the user must print this emergency kit, write the password in it and kept the file in a safe place. **In this project we won't cover this recovery method.**

## Loging from new client steps

1. The user logs in with its password and secret key.

2. Server returns its key sets.

3. User negotiate the SRP.

4. The server validates the user and in a success case returns its keyset.

## Normal Unlock steps

1. User enter its password.

2. Device generates AUK, decrypt its private key.

> **NOTE:** In this case the user has a copy of its vaults and can work ofline

## Vault creation steps

1. First a secure 256-bit key is generated, each vault must have its own key.

2. Then the vault secret key is saved encrypted with the user's public key.

3. Every item in the vault is encrypted with the secret key. Except for the overview data such as tite, web site, timestamps, etc.

4. The holle vault is encrypted with the secret key.

## Vault sharing steps

1. The User shares encrypt the vault secret key with the invited user public key.

2. Send the encrypted secret key tho the invited user.

## Vault item sharing steps

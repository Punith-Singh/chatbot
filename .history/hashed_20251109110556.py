import hashlib
import hmac

def verify_pbkdf2_hash(stored, candidate_password):
    # stored format: "pbkdf2:sha256:600000$salt$hexhash"
    try:
        algo_part, salt, hexhash = stored.split('$')
        _prefix, hash_name, iterations_str = algo_part.split(':')  # e.g. ["pbkdf2","sha256","600000"]
        iterations = int(iterations_str)
    except Exception as e:
        raise ValueError("Unexpected stored-hash format") from e

    # derive key from candidate
    dk = hashlib.pbkdf2_hmac(hash_name, candidate_password.encode('utf-8'), salt.encode('utf-8'), iterations)
    derived_hex = dk.hex()

    # Use constant-time comparison
    return hmac.compare_digest(derived_hex, hexhash)

# Example usage (ONLY run for accounts you own / have permission to test):
stored = "pbkdf2:sha256:600000$0U90bDFoEjZQstW9$415f63c2e79e29b78d0e7c47dfd12ef5c991453b09ab03ded8fb8fb302b90330"
candidate = "punith"
if verify_pbkdf2_hash(stored, candidate):
    print("Password matches")
else:
    print("Password does NOT match")

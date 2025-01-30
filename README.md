# Convert JWK to PEM with Validation

## Overview

This script, `jwk_to_pem_with_validation.py`, converts an **RSA JSON Web Key (JWK)** into a standard **PEM-encoded RSA private key**. It also includes validation functionality to ensure the generated key is correct and extracts the public key.

## Prerequisites

Ensure you have Python 3 installed along with the necessary dependencies. You can install the required package using:

```python
pip install cryptography
```

or

```python
pip install -r ./requirements.txt
```



## Usage

### 1. **Prepare the JWK file**

Save your **RSA JWK** as a JSON file in the same location as the script, e.g., `test_key.jwk`. The structure should resemble the following:

```json
{
    "key": {
        "kty": "RSA",
        "n": "...",  
        "e": "AQAB",
        "d": "...",  
        "p": "...",
        "q": "...",
        "dp": "...",
        "dq": "...",
        "qi": "..."
    }
}
```

or, update line 77 to point to your JWK instead of test_key.jwk

```python
    # Load the JWK from file (update filename if needed)
    with open("test_key.jwk", "r") as f:
        jwk_data = json.load(f)["key"]
```



### 2. **Run the script**

Execute the script with:

```python
python jwk_to_pem_with_validation.py
```

### 3. **Output Files**

After running the script, the following files will be generated:

- `rsa_private.pem`: The **converted RSA private key** in PEM format.
- `rsa_public.pem`: The **extracted RSA public key** in PEM format.

### 4. **Expected Output**

Upon execution, you should see output similar to:

```python
🔑 RSA Private Key saved as rsa_private.pem

🔍 Validating RSA Key...
✅ RSA Key is valid
Modulus (n): output_value_here
Exponent (e): output_value_here
🔓 RSA Public Key saved as rsa_public.pem
```

### 5. **Validating the Output**

You can verify the generated PEM key using **OpenSSL**:

#### Check the private key format:

```bash
openssl rsa -in rsa_private.pem -check
```

Output:

```bash
RSA key ok
```

#### Extract and verify the public key:

```bash
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
openssl rsa -in rsa_public.pem -pubin -text -noout
```

This should match the modulus (`n`) and exponent (`e`) from the original JWK.

## Notes

- The script supports **PKCS#8** format for better compatibility.
- If you need an **encrypted private key**, update the script to pass a password using `serialization.BestAvailableEncryption(b'password')`.
- If you encounter issues, ensure that the JWK is properly formatted and includes all necessary fields (`n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`).
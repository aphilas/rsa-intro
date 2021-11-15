import random
import typer
from Crypto.Util.number import getPrime
from pathlib import Path
from typing import Optional
import pickle

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def egcd(a,b):
    if b==0:
        return (1,0)

    (q,r) = (a//b,a%b)
    (s,t) = egcd(b,r)

    return (t, s-(q*t))

def modinv(x,y):
    inv = egcd(x,y)[0]

    if inv < 1: 
        inv += y
        return inv

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def genprimes(n, e):
    p, q = 0, 0

    while p == q or p % e == 1 or q % e == 1:
        p = getPrime(int(n/2))
        q = getPrime(int(n-n/2))

    if p < q:
        p, q = q, p

    return p, q

def genkey(p, q):    
    n = p * q
    phi = (p-1) * (q-1)

    # e
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = modinv(e, phi)
    
    # public, private
    return ((e, n), (d, n))

def enc(pk, plaintext):
    key, n = pk
    cipher = [(ord(char) ** key) % n for char in plaintext]
    return cipher

def dec(pk, ciphertext):
    key, n = pk
    plain = [chr((char ** key) % n) for char in ciphertext]
    return ''.join(plain)

app = typer.Typer()

def flatten(t):
    return [item for sublist in t for item in sublist]

@app.command()
def keygen(
        private: Optional[Path] = typer.Option('public.pickle', file_okay=True, dir_okay=False, writable=True), 
        public: Optional[Path] = typer.Option('private.pickle', file_okay=True, dir_okay=False, writable=True)
    ):

    typer.echo("Generating keys...")

    e = 257
    k = 1 << 4 # 16-bit key - faster for testing  
    p, q = genprimes(k, e)
    pub, priv = genkey(p, q)

    while not all(map(lambda v: bool(v), flatten([ pub, priv]))):
        pub, priv = genkey(p, q)

    with open(public, 'wb') as fh:
        pickle.dump(pub, fh, protocol=pickle.HIGHEST_PROTOCOL)

    with open(private, 'wb') as fh:
        pickle.dump(priv, fh, protocol=pickle.HIGHEST_PROTOCOL)

    typer.echo(f"Saved {public} and {private}")

@app.command()
def encrypt(
        message: str,
        key: Optional[Path] = typer.Option('public.pickle', file_okay=True, dir_okay=False),
    ):

    if not key.is_file():
        typer.echo("Key file does not exist")
        raise typer.Abort()

    typer.echo(f"Encrypting \"{message}\" using {key}")

    try:
        with open(key, 'rb') as fh:
                pub = pickle.load(fh)
                cipher = enc(pub, message)
                typer.echo(f"{ ''.join(list(map(lambda v: hex(v), cipher))) }")
    except pickle.UnpicklingError:
        typer.echo("Error reading key")
    except (AttributeError,  EOFError, ImportError, IndexError) as e:
        print(traceback.format_exc(e))
    except Exception as e:
        print(traceback.format_exc(e))
        return

@app.command()
def decrypt(
        cipher: str,
        key: Optional[Path] = typer.Option('private.pickle', file_okay=True, dir_okay=False),
    ):

    if not key.is_file():
        typer.echo("Key file does not exist")
        raise typer.Abort()

    typer.echo(f"Decrypting \"{cipher}\" using {key}")

    try:
        with open(key, 'rb') as fh:
                priv = pickle.load(fh)
                it = list(map(lambda v: int('0x'+v, 16), filter(None, cipher.split('0x'))))
                message = dec(priv, it)
                typer.echo(f"{ message }")
    except pickle.UnpicklingError:
        typer.echo("Error reading key")
    except (AttributeError,  EOFError, ImportError, IndexError) as e:
        print(traceback.format_exc(e))
    except Exception as e:
        print(traceback.format_exc(e))
        return

if __name__ == '__main__':
    app()
    
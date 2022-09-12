import hashlib


# -----ConstBitcoin-----
class Curve:  # генерация кривой
    def __init__(self, p: int, a: int, b: int):
        self.p = p
        self.a = a
        self.b = b

# bitcoin расположен на кривой secp256k1(a = 0, b = 7)  # secp256k1
bitcoin_curve = Curve(
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, # mod
    a = 0x0000000000000000000000000000000000000000000000000000000000000000, # a = 0
    b = 0x0000000000000000000000000000000000000000000000000000000000000007, # b = 7
)


class Point:  # создания базовой точки  # BasePoint
    def __init__(self, curve: Curve, x: int, y: int):
        self.curve = bitcoin_curve  # Curve REMOVE
        self.x = x
        self.y = y

    def __add__(self, other):  # __add__ позволяет складывать 
        # P + 0 = 0 + P = 0
        if self == INF:
            return other
        if other == INF:
            return self
        # P + (-P) = 0
        if self.x == other.x and self.y != other.y:
            return INF
        # вычисления наклона
        if self.x == other.x:
            m = (3 * self.x**2 + self.curve.a) * inv(2 * self.y, self.curve.p)
        else:
            m = (self.y - other.y) * inv(self.x - other.x, self.curve.p)
        # создание новой точки
        rx = (m**2 - self.x - other.x) % self.curve.p
        ry = (-(m*(rx - self.x) + self.y)) % self.curve.p
        return Point(self.curve, rx, ry)

    def __rmul__(self, k: int):  # __rmul__ позволяет умножать
        assert isinstance(k, int) and k >= 0
        result = INF
        append = self
        while k:
            if k & 1:
                result += append
            append += append
            k >>= 1
        return result

G = Point(
    bitcoin_curve,
    x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)

class Generator:  # указание порядка группы REMOVE
    def __init__(self, G: Point, n: int):
        self.G = G
        self.n = n

bitcoin_gen = Generator(
    G = G,
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)

# -----SecretKey-----
secret_key = int.from_bytes(b'Andrej is cool :P', 'big')  # перевод строки(в байтах) в число + главная фраза(Andrej is cool :P)
assert 1 <= secret_key < bitcoin_gen.n, 'SecretKey не удовлетворяет условию'  # проверка на True

# -----PublicKey----- 
INF = Point(None, None, None)

def extended_euclidean_algorithm(a, b):  # НОД(расширеный алгорит Евклида, наибольший ОД)
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t

def inv(n, p):  # возвращает целое число m, при котором (n * m) % p == 1
    gcd, x, y = extended_euclidean_algorithm(n, p)
    assert (n * x + p * y) % p == gcd
    if gcd != 1:
        raise ValueError('{} не имеет обратного умножения по модулю {}'.format(n, p))
    else:
        return x % p  # возвращает обратную величину n по модулю p

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58encode(b: bytes) -> str:
    assert len(b) == 25
    n = int.from_bytes(b, 'big')
    chars = []
    while n:
        n, i = divmod(n, 58)
        chars.append(alphabet[i])
    # вычисления 0-го байта
    num_leading_zeros = len(b) - len(b.lstrip(b'\x00'))
    res = num_leading_zeros * alphabet[0] + ''.join(reversed(chars))
    return res

class PublicKey(Point):

    @classmethod
    def from_point(cls, pt: Point):
        return cls(pt.curve, pt.x, pt.y)

    def encode(self, compressed, hash160=False):
        if compressed:
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            pkb = prefix + self.x.to_bytes(32, 'big')
        else:
            pkb = b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
        return hashlib.new('ripemd160', hashlib.sha256(pkb).digest()).digest()  # hash по желанию

    def address(self, net: str, compressed: bool) -> str:
        pkb_hash = self.encode(compressed=compressed, hash160=True)
        version = {'main': b'\x00', 'test': b'\x6f'}
        ver_pkb_hash = version[net] + pkb_hash
        checksum = hashlib.sha256(hashlib.sha256(ver_pkb_hash).digest()).digest()[:4]
        byte_address = ver_pkb_hash + checksum
        b58check_address = b58encode(byte_address)
        return b58check_address


# -----TEST-----
public_key = secret_key * G
address = PublicKey.from_point(public_key).address(net='test', compressed=True)  # main
print(address)

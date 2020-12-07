from bleichenbacher import Bleichenbacher
from util import power, modinv

import os
import secrets

class BasicRSA:
  # Set up an RSA modulus with prime factors p, q and messages of size
  # msg_bytes
  def __init__(self, p, q, msg_bytes):
    self.p = p
    self.q = q

    self.N = self.p * self.q
    self.phiN = (self.p - 1) * (self.q - 1)
    self.e = 3
    self.d = modinv(self.e, self.phiN)

    k = self.N - 1
    self.N_bytes = 0
    while k > 0:
      k >>= 1
      self.N_bytes += 1
    self.N_bytes = (self.N_bytes + 7) // 8

    self.msg_bytes = msg_bytes
    self.padding_bytes = self.N_bytes - self.msg_bytes - 3

    self.oracle_calls = 0

  def get_public_key(self):
    return self.N, self.e

  # PKCS#1 encryption
  def encrypt(self, m):
    # Apply PKCS#1 padding to the message
    pad = [secrets.choice(range(1, 256)) for i in range(self.padding_bytes)]
    padded_msg = b'\x00\x02' + bytes(pad) + b'\x00' + (m).to_bytes(self.msg_bytes, 'big')
    val = int.from_bytes(padded_msg, byteorder = 'big')

    # Compute c = m^e mod N using repeated squaring
    ctxt = power(val, self.e, self.N)

    return ctxt

  # Check that mesage starts with 00 02
  def check_pad(self, m):
    m_bytes = (m).to_bytes(self.N_bytes, 'big')
    if m_bytes[0] != 0 or m_bytes[1] != 2:
      return False

    return True

  # Strips away the padding
  def unpad(self, padded_msg):
    msg_bytes = (padded_msg).to_bytes(self.N_bytes, 'big')
    return int.from_bytes(msg_bytes[3 + self.padding_bytes:], byteorder = 'big')

  # PKCS#1 decryption
  def decrypt(self, ctxt):
    val = power(ctxt, self.d, self.N)
    if not self.check_pad(val):
      return None

    return self.unpad(val)

  # Checks if ctxt is an encryption of a PKCS#1-padded message
  # (for simplicity, we say a message is properly padded if its leading
  #  first two bytes is 00 02 -- as computed by check_pad)
  def padding_oracle(self, ctxt):
    self.oracle_calls += 1
    return self.decrypt(ctxt) is not None

# 64-bit primes for testing purposes
bits = 64
if bits == 64:
	P = 13382524637124739259
	Q = 16561004363178600341
elif bits == 128:
	P = 302259847198242230891766592673900587973
	Q = 333239335742497844449788547405994924693
elif bits == 256:
	P = 91903492234199378649198832762472663389765415829680438630952887571845353694399
	Q = 99129552124407696950379076966517939961983123774707779850388464784864294525957
elif bits == 512:
	P = 10964890478323192448272590244559648809700604775703790103867938313773539971042659610624125019860897394642912575824680765006011443683681586348532000158817131
	Q = 12713584634065617144786664005465927767659747646494129569226246966810998637601362468405550092928063298362088310391238706063126351805519303585199046035575141
elif bits == 1024:
	P = 175085980259687696149046076582048358603739789430723704974174136131974133355499249234724915489434904045231039449132375021373323615476000650036451466874542438941477724582551122760107173647527913559739423070846942255478057973131794782093182509270658683626418492657308198032507764969396758863020477678870005533377
	Q = 173481182901003033631786302587161042180815118571727358720397882595172403501543129732599144971354172513383539052340381993913462460557507697207203586672226159267321343114459105131182356343805628894672458701827874872632273469026603248423273138495471077401856689648171996263785914959717062423792528287237534136819

# Construct the RSA instance for encrypting 8-byte messages
msg_bytes = 8
rsa = BasicRSA(P, Q, msg_bytes)
N, e = rsa.get_public_key()

# Sample a random secret and encrypt it using RSA with PKCS#1 padding
secret = os.urandom(msg_bytes)
print('Encrypting key', secret.hex())
ctxt = rsa.encrypt(int.from_bytes(secret, byteorder = 'big'))

# Invoke Bleichenbacher's padding oracle attack on the ciphertext
padded_msg = Bleichenbacher(N, e).decrypt(ctxt, rsa.padding_oracle)
msg = (rsa.unpad(padded_msg)).to_bytes(msg_bytes, byteorder = 'big')
print('Recovered key ', msg.hex())

print('Number of oracle calls made:', rsa.oracle_calls)

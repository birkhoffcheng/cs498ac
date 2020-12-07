from util import power, modinv, egcd

class Bleichenbacher:
	def __init__(self, N, e):
		self.N = N
		self.e = e
		self.k = (self.N.bit_length() + 7) // 8

	def ceil(self, a, b):
		return (a + b - 1) // b

	def floor(self, a, b):
		return a // b

	def find_smallest_s(self, lo, c, oracle):
		s = lo
		while not oracle((c * power(s, self.e, self.N)) % self.N):
			s += 1
		return s

	def find_s_in_interval(self, a, b, s_i_1, B, c, oracle):
		ri = self.ceil(2 * (b * s_i_1 - 2 * B), self.N)
		while True:
			si_lo = self.ceil(2 * B + ri * self.N, b)
			si_hi = self.ceil(3 * B + ri * self.N, a)
			for s in range(si_lo, si_hi):
				if oracle((c * power(s, self.e, self.N)) % self.N):
					return s
			ri += 1

	def union_intervals(self, M, lo, hi):
		for i, (a, b) in enumerate(M):
			if a <= hi and b >= lo:
				M[i] = (min(lo, a), max(hi, b))
				return M
		M.append((lo, hi))
		return M

	def update_intervals(self, M, s, B):
		M_i = []
		for a, b in M:
			r_lo = self.ceil(a * s - 3 * B + 1, self.N)
			r_hi = self.ceil(b * s - 2 * B, self.N)
			for r in range(r_lo, r_hi):
				lower = max(a, self.ceil(2 * B + r * self.N, s))
				upper = min(b, self.floor(3 * B - 1 + r * self.N, s))
				M_i = self.union_intervals(M_i, lower, upper)
		return M_i

	def decrypt(self, ctxt, oracle):
		# Step 1
		s0 = self.find_smallest_s(0, ctxt, oracle)
		c0 = (ctxt * power(s0, self.e, self.N)) % self.N
		B = 2 ** (8 * (self.k - 2))
		M = [(2 * B, 3 * B - 1)]

		# Step 2.a
		s = self.find_smallest_s(self.ceil(self.N, 3 * B), c0, oracle)
		M = self.update_intervals(M, s, B)

		while True:
			# Step 2.b
			if len(M) > 1:
				s = self.find_smallest_s(s + 1, c0, oracle)

			elif len(M) == 1:
				a, b = M[0]

				# Step 4
				if a == b:
					return (a * modinv(s0, self.N)) % self.N

				# Step 2.c
				s = self.find_s_in_interval(a, b, s, B, c0, oracle)

			else:
				return 0

			# Step 3
			M = self.update_intervals(M, s, B)
		return 0

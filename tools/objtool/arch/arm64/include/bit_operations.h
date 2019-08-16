#ifndef _BIT_OPERATIONS_H
#define _BIT_OPERATIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <linux/types.h>

#define ONES(N)			(((__uint128_t)1 << (N)) - 1)
#define ZERO_EXTEND(X, N)	((X) & ONES(N))
#define EXTRACT_BIT(X, N)	(((X) >> (N)) & ONES(1))
#define SIGN_EXTEND(X, N)	((((unsigned long)-1 + (EXTRACT_BIT(X, (N) - 1) ^ 1)) << (N)) | X)

u64 replicate(u64 x, int size, int n);

u64 ror(u64 x, int size, int shift);

int highest_set_bit(u32 x);

__uint128_t decode_bit_masks(unsigned char N,
			     unsigned char imms,
			     unsigned char immr,
			     bool immediate);

#endif /* _BIT_OPERATIONS_H */

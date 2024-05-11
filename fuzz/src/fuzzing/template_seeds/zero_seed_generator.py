import random

# for i in range(5):
#     seed_path = 'afl_seeds/random.seed.len40.' + str(i)
#     with open(seed_path, 'wb') as f:
#         for i in range(40):
#             b = random.randint(0,255)
#             f.write(bytes([b]))


seed_path = 'binary/rfuzz-zero-len500.hwf'
with open(seed_path, 'wb') as f:
    for i in range(500):
        b = 0
        f.write(bytes([b]))




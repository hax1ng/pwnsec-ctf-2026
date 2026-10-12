import secrets


width = 8
rate = 16
rounds = [
    0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01,
    0x81, 0x09, 0x8a, 0x88, 0x09, 0x0a,
    0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80,
]
offsets = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
places = [0, 1, 2, 4, 6, 10, 11, 12, 13, 14, 15, 18, 19, 20, 22]


def rot(value, shift):
    shift %= width
    return ((value << shift) | (value >> (width - shift))) & 0xff


def theta(state):
    columns = [
        state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
        for x in range(5)
    ]
    drift = [
        columns[(x - 1) % 5] ^ rot(columns[(x + 1) % 5], 1)
        for x in range(5)
    ]
    return [state[x + 5 * y] ^ drift[x] for y in range(5) for x in range(5)]


def shift(state):
    out = [0] * 25
    for y in range(5):
        for x in range(5):
            out[y + 5 * ((2 * x + 3 * y) % 5)] = rot(
                state[x + 5 * y], offsets[x][y]
            )
    return out


def chi(state):
    out = [0] * 25
    for y in range(5):
        for x in range(5):
            out[x + 5 * y] = state[x + 5 * y] ^ (
                (~state[(x + 1) % 5 + 5 * y])
                & state[(x + 2) % 5 + 5 * y]
            )
    return [value & 0xff for value in out]


def finish(state, constant):
    out = chi(state)
    out[0] ^= constant
    return out


def step(state, constant):
    return finish(shift(theta(state)), constant)


def turn(state):
    state = list(state)
    for constant in rounds:
        state = step(state, constant)
    return state


def padded(message):
    out = message + b"\x1f"
    out += b"\x00" * ((-len(out) - 1) % rate)
    return out + b"\x80"


def opened(key, fog):
    return turn(key + fog)


def seal(key, fog, message):
    state = opened(key, fog)
    data = padded(message)
    for start in range(0, len(data), rate):
        block = data[start:start + rate]
        for index in range(rate):
            state[index] ^= block[index]
        state = turn(state)
    return bytes(state)


def edge(key, fog, message):
    state = opened(key, fog)
    data = padded(message)
    blocks = [data[start:start + rate] for start in range(0, len(data), rate)]
    for block in blocks[:-1]:
        for index in range(rate):
            state[index] ^= block[index]
        state = turn(state)
    for index in range(rate):
        state[index] ^= blocks[-1][index]
    for constant in rounds[:-3]:
        state = step(state, constant)
    return state


def tail(state):
    state = list(state)
    for constant in rounds[-3:]:
        state = step(state, constant)
    return state


def peek(state):
    return bytes(state[x + 5 * y] for y in range(2) for x in range(4))


def tag(state):
    return bytes(state[x + 5 * y] for y in range(3) for x in range(4))


def shuffle(values):
    values = list(values)
    for index in range(len(values) - 1, 0, -1):
        place = secrets.randbelow(index + 1)
        values[index], values[place] = values[place], values[index]
    return values


def rank(values):
    base = {}
    for value in values:
        work = value
        while work:
            bit = work.bit_length() - 1
            if bit in base:
                work ^= base[bit]
            else:
                base[bit] = work
                break
    return len(base)


def shape(value, choices):
    out = 0
    for index, choice in enumerate(choices):
        if choice & ~value == 0:
            out |= 1 << index
    return out


def mark(value, choices, rows):
    sample = shape(value, choices)
    out = 0
    for index, row in enumerate(rows):
        out |= ((row & sample).bit_count() & 1) << index
    return out


def paint(value, choices, rows):
    return mark(value, choices, rows).to_bytes(3, "little")


def stray(before):
    first = secrets.randbelow(25)
    second = secrets.randbelow(24)
    if second >= first:
        second += 1
    state = before[:]
    state[first] ^= secrets.randbelow(255) + 1
    state[second] ^= secrets.randbelow(255) + 1
    return peek(tail(state))

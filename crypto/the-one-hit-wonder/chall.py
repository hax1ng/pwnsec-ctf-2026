import os
from secrets import randbelow
from Crypto.Util.number import getStrongPrime


def take(s):
    return int(input(s).strip())
def top(x, k, n):
    return x >> (n - k)




def main():
    p = int(getStrongPrime(1536))
    n = p.bit_length()
    k = (58 * n) // 100
    cap = 8
    u = randbelow(p)
    v = randbelow(p - 1) + 1
    seen = set()
    bag = []
    flag = os.getenv('FLAG', 'pwnsec{????????????????}')

    while True:
        print('1) info')
        print('2) tap')
        print('3) log')
        print('4) check')
        print('5) quit')
        c = input('> ').strip()

        if c == '1':
            print(f'p = {p}')
            print(f'bits = {n}')
            print(f'keep = {k}')
            print(f'left = {cap - len(bag)}')
        elif c == '2':
            if len(bag) >= cap:
                print('locked')
                continue
            t = take('x = ')
            if t is None:
                print('bad')
                continue
            t %= p
            if t in seen or (t + u) % p == 0:
                print('bad')
                continue
            z = (v * pow((t + u) % p, -1, p)) % p
            h = top(z, k, n)
            seen.add(t)
            bag.append((t, h))
            print(f't = {t}')
            print(f'y = {h}')
        elif c == '3':
            for i, (t, h) in enumerate(bag):
                print(f'{i}: {t} {h}')
        elif c == '4':
            a = take('a = ')
            b = take('b = ')
            if a is None or b is None:
                print('bad')
                continue
            if a % p == u and b % p == v:
                print(flag)
                return
            print('no')
        elif c == '5':
            return
        else:
            print('bad')


if __name__ == '__main__':
    main()

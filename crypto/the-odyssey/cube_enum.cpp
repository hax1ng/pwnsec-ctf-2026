// Stage 3b: fast OpenMP enumeration of the transformed hyperplane normals that satisfy the cube equations.
// Build: g++ -O3 -march=native -fopenmp cube_enum.cpp -o cube_enum
#include <bits/stdc++.h>
#include <omp.h>
using namespace std;
using U = uint64_t;

struct V2 { U a, b; };
inline bool vz(V2 x) { return !(x.a | x.b); }
inline V2 vx(V2 x, V2 y) { return {x.a ^ y.a, x.b ^ y.b}; }
inline int vtop(V2 x) {
    return x.b ? 64 + (63 - __builtin_clzll(x.b))
               :      (63 - __builtin_clzll(x.a));
}
struct C3 { U x[3]; };
inline void cx(C3 &a, const C3 &b) {
    a.x[0] ^= b.x[0]; a.x[1] ^= b.x[1]; a.x[2] ^= b.x[2];
}
struct Mat { U x[8]; };
inline void mx(Mat &a, const Mat &b) {
    for (int i = 0; i < 8; ++i) a.x[i] ^= b.x[i];
}
inline U meval(const Mat &m, int n) {
    U z = 0;
    while (n) { int b = __builtin_ctz(n); z ^= m.x[b]; n &= n - 1; }
    return z;
}

struct Lin128 {
    bool has[128]{}; V2 pv[128]{}; C3 pc[128]{};
    vector<C3> ker; int rk = 0, nd;
    explicit Lin128(int n) : nd(n) {}
    void add(V2 v, int idx) {
        C3 c{}; c.x[idx >> 6] |= 1ULL << (idx & 63);
        while (!vz(v)) {
            int p = vtop(v);
            if (has[p]) { v = vx(v, pv[p]); cx(c, pc[p]); }
            else { has[p] = true; pv[p] = v; pc[p] = c; ++rk; return; }
        }
        ker.push_back(c);
    }
    bool solve(V2 v, C3 &c) const {
        c = {};
        while (!vz(v)) {
            int p = vtop(v); if (!has[p]) return false;
            v = vx(v, pv[p]); cx(c, pc[p]);
        }
        return true;
    }
};

int rank8(initializer_list<int> vals) {
    int p[8]{}; int r = 0;
    for (int x : vals) while (x) {
        int b = 31 - __builtin_clz(x);
        if (p[b]) x ^= p[b]; else { p[b] = x; ++r; break; }
    }
    return r;
}
struct B64 {
    U p[64]{}; bool h[64]{};
    void add(U x) { while (x) {
        int b = 63 - __builtin_clzll(x);
        if (h[b]) x ^= p[b]; else { h[b] = true; p[b] = x; return; }
    }}
    U red(U x) const { while (x) {
        int b = 63 - __builtin_clzll(x);
        if (!h[b]) return x; x ^= p[b];
    } return 0; }
};

bool within_units(const B64 &b, U diff, int count) {
    U rem = b.red(diff);
    if (count == 0) return rem == 0;
    U us[64];
    for (int i = 0; i < 64; ++i) us[i] = b.red(1ULL << i);
    if (count == 1) {
        for (U u : us) if (u == rem) return true;
        return false;
    }
    // Two one-bit corruptions. They may occur in the same output bit and cancel.
    unordered_set<U> setu(us, us + 64);
    for (U u : us) if (setu.count(rem ^ u)) return true;
    return false;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    ifstream f(argv[1]);
    int pos, nd, d; U top;
    f >> pos >> hex >> top >> dec >> nd >> d;
    Mat base{}; for (auto &x : base.x) f >> hex >> x;
    vector<Mat> D(nd); for (auto &m : D) for (auto &x : m.x) f >> hex >> x;
    vector<int> hs(d); vector<U> vs(d); vector<string> ep(d);
    for (int j = 0; j < d; ++j) f >> hex >> hs[j] >> vs[j] >> ep[j];
    vector<U> w(d); vector<int> ew(d);
    for (int j = 0; j < d; ++j) {
        w[j] = vs[j] ^ ((hs[j] & 1) ? top : 0);
        ew[j] = count(ep[j].begin(), ep[j].end(), '1');
    }
    if (d < 3 || ew[0] || ew[1] > 1) return 2;
    vector<array<int,4>> matches;
    double started = omp_get_wtime();
    #pragma omp parallel for schedule(dynamic)
    for (int n1 = 1; n1 < 256; ++n1) for (int n2 = 1; n2 < 256; ++n2) {
        if (n1 == n2) continue;
        Lin128 A(nd);
        for (int k = 0; k < nd; ++k)
            A.add({meval(D[k], n1), meval(D[k], n2)}, k);
        // The adapted first cube is exact.  Usually the second is exact too;
        // in the rank-eight bad-point case it contains one of the two known
        // one-bit corruptions.  Keep all possible corrected right-hand sides.
        vector<U> corrections2;
        if (ew[1] == 0) corrections2.push_back(0);
        else for (int bit=0; bit<64; ++bit) corrections2.push_back(1ULL<<bit);
        C3 refsol{}; bool gotref=false; vector<C3> sols;
        for (U corr : corrections2) {
            C3 sol;
            if (A.solve({w[0]^meval(base,n1), w[1]^meval(base,n2)^corr},sol)) {
                if (!gotref) { refsol=sol;gotref=true; }
                sols.push_back(sol);
            }
        }
        if (!gotref) continue;
        Mat pm = base;
        for (int k = 0; k < nd; ++k)
            if ((refsol.x[k>>6] >> (k&63)) & 1) mx(pm, D[k]);
        // Effect of choosing each alternative correction for cube two.
        vector<Mat> alternatives;
        for (auto sol : sols) {
            cx(sol,refsol); Mat q{};
            for (int k=0;k<nd;++k)
                if ((sol.x[k>>6]>>(k&63))&1) mx(q,D[k]);
            alternatives.push_back(q);
        }
        vector<Mat> km; km.reserve(A.ker.size());
        for (auto &co : A.ker) {
            Mat q{};
            for (int k = 0; k < nd; ++k)
                if ((co.x[k>>6] >> (k&63)) & 1) mx(q, D[k]);
            km.push_back(q);
        }
        for (int n3 = 1; n3 < 256; ++n3) {
            if (n3 == n1 || n3 == n2 || n3 == (n1 ^ n2)) continue;
            B64 b; for (auto &q : km) b.add(meval(q,n3));
            bool third_ok=false;
            if (ew[1]==0) {
                third_ok=within_units(b,w[2]^meval(pm,n3),ew[2]);
            } else {
                // In this branch the two error-evaluation functionals are
                // independent, so cube three also contains one unit error.
                U unit_synd[64]; unordered_set<U> allowed;
                for (int bit=0;bit<64;++bit) {
                    unit_synd[bit]=b.red(1ULL<<bit);
                    if (ew[2]==1) allowed.insert(unit_synd[bit]);
                }
                U rem0=b.red(w[2]^meval(pm,n3));
                for (auto &alt:alternatives) {
                    U rem=rem0^b.red(meval(alt,n3));
                    if ((ew[2]==0 && rem==0) || (ew[2]==1 && allowed.count(rem))) {
                        third_ok=true;break;
                    }
                }
            }
            if (!third_ok) continue;
            int n4 = 0;
            if (d >= 4) {
                for (int z = 1; z < 256; ++z) {
                    if (rank8({n1,n2,n3,z}) != 4) continue;
                    B64 bz; for (auto &q : km) bz.add(meval(q,z));
                    if (within_units(bz, w[3] ^ meval(pm,z), ew[3])) { n4=z; break; }
                }
                if (!n4) continue;
            }
            #pragma omp critical
            {
                matches.push_back({n1,n2,n3,n4});
                cout << "MATCH " << dec << pos << ' ' << hex
                     << n1 << ' ' << n2 << ' ' << n3 << ' ' << n4
                     << dec << "\n";
            }
        }
    }
    cerr << "done pos=" << pos << " seconds=" << (omp_get_wtime()-started)
         << " matches=" << matches.size() << "\n";
}

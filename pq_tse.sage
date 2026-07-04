# Post-Quantum Topological Symmetric Encryption (PQ-TSE)
# Based on the Secret Pachner Path Problem (SP3)
# Hard Problem: Finding the secret sequence of Pachner moves
#               that transforms a scrambled triangulation back
#               to its canonical form.

import random

#---------------------------------------------------------------
# Public Primitives:
# Grid Torus as the canonical manifold - the standard reference
# form agreed upon by both parties.
GRID_M, GRID_N = 10, 10  # Grid 10x10 = 100 vertices, 300 edges, 200 triangles
NUM_MOVES = 500          # Number of secret Pachner moves (security parameter)
#---------------------------------------------------------------

def build_grid_torus(m, n):
    """
    Construct the canonical Grid Torus from an m x n grid.
    Vertices are labeled (i, j) with toroidal boundary conditions.
    Each grid cell is subdivided into 2 triangles.
    """
    triangles = []
    for i in range(m):
        for j in range(n):
            v00 = (i, j)
            v10 = ((i + 1) % m, j)
            v01 = (i, (j + 1) % n)
            v11 = ((i + 1) % m, (j + 1) % n)
            triangles.append((v00, v10, v01))
            triangles.append((v10, v11, v01))
    return SimplicialComplex(triangles)

def find_valid_2_2_moves(K):
    """
    Find all valid (2,2) Pachner moves in complex K.
    A (2,2) move flips an interior edge shared by exactly 2 triangles,
    replacing the edge with its dual diagonal.
    Validity condition: the new diagonal edge must not already exist.
    """
    edges = list(K.faces()[1])
    triangles = list(K.faces()[2])
    edge_set_all = {frozenset(e) for e in edges}
    tri_set_all = {frozenset(t) for t in triangles}
    
    valid_moves = []
    for edge in edges:
        edge_fs = frozenset(edge)
        containing = [t for t in triangles if edge_fs.issubset(frozenset(t))]
        if len(containing) != 2:
            continue
        tri1, tri2 = containing
        a, b = list(edge)
        c = list(set(tri1) - set(edge))[0]
        d = list(set(tri2) - set(edge))[0]
        new_edge = frozenset([c, d])
        if new_edge in edge_set_all:
            continue
        new_tri1 = frozenset([a, c, d])
        new_tri2 = frozenset([b, c, d])
        if new_tri1 in tri_set_all or new_tri2 in tri_set_all:
            continue
        valid_moves.append({
            'edge': tuple(sorted(edge)),
            'tri1': tuple(sorted(tri1)),
            'tri2': tuple(sorted(tri2)),
            'new_edge': tuple(sorted([c, d])),
            'new_tri1': tuple(sorted([a, c, d])),
            'new_tri2': tuple(sorted([b, c, d])),
            'a': a, 'b': b, 'c': c, 'd': d
        })
    return valid_moves

def apply_2_2_move_to_complex(K, move):
    """
    Apply a (2,2) Pachner move to the simplicial complex.
    Removes the 2 old triangles and adds 2 new triangles.
    The global topology (homology) is preserved.
    """
    old_tri1 = set(move['tri1'])
    old_tri2 = set(move['tri2'])
    new_triangles = []
    for t in K.faces()[2]:
        t_set = set(t)
        if t_set == old_tri1 or t_set == old_tri2:
            continue
        new_triangles.append(tuple(sorted(t)))
    new_triangles.append(move['new_tri1'])
    new_triangles.append(move['new_tri2'])
    return SimplicialComplex(new_triangles)

def apply_2_2_move_to_path(path, move):
    """
    Apply a (2,2) Pachner move to a path (message cycle).
    If the path contains the flipped edge, replace it with the
    3-edge alternative path through the dual diagonal.
    Uses stack-based directed edge cancellation to maintain
    homology class invariance.
    """
    a, b = move['a'], move['b']
    c, d = move['c'], move['d']
    
    directed_edges = [(path[i], path[i+1]) for i in range(len(path)-1)]
    new_edges = []
    
    for u, v in directed_edges:
        if u == a and v == b:
            new_edges.extend([(a, c), (c, d), (d, b)])
        elif u == b and v == a:
            new_edges.extend([(b, d), (d, c), (c, a)])
        else:
            new_edges.append((u, v))
    
    stack = []
    for u, v in new_edges:
        if stack and stack[-1] == (v, u):
            stack.pop()
        else:
            stack.append((u, v))
    
    if not stack:
        return [path[0]]
    
    new_path = [stack[0][0]]
    for u, v in stack:
        new_path.append(v)
    return new_path

#---------------------------------------------------------------
# Key Generation (Shared Secret between Alice and Bob):
# Both parties agree on a canonical Torus and a random sequence
# of Pachner moves. This sequence is the shared secret key.

T_canonical = build_grid_torus(GRID_M, GRID_N)
K_curr = T_canonical
shared_secret = []

for step in range(NUM_MOVES):
    valid_moves = find_valid_2_2_moves(K_curr)
    chosen = random.choice(valid_moves)
    shared_secret.append(chosen)
    K_curr = apply_2_2_move_to_complex(K_curr, chosen)

scrambled_torus = K_curr  # Public reference (not secret)
sk = shared_secret        # Shared secret key (must be distributed securely)

print('Scrambled Torus: ', len(scrambled_torus.vertices()), 'V,', 
      len(scrambled_torus.faces()[1]), 'E,', len(scrambled_torus.faces()[2]), 'T')
print('Shared secret:   ', len(sk), ' Pachner moves')

#---------------------------------------------------------------
# Alice Secret Message:
# The message is encoded as a 1-cycle (closed path) in the
# canonical Torus.

message_path = [(0, j) for j in range(GRID_N)] + [(0, 0)]
print('Alice plaintext (cycle): ', len(message_path), 'vertices')

#---------------------------------------------------------------
# Encryption (Alice applies shared secret to the message):
# Alice uses the shared secret to scramble the message cycle.

path_curr = message_path.copy()

for move in sk:
    path_curr = apply_2_2_move_to_path(path_curr, move)

ciphertext = path_curr
print('Alice sends ciphertext: ', len(ciphertext), 'vertices')

#---------------------------------------------------------------
# Decryption (Bob applies inverse of shared secret):
# Bob uses the same shared secret to recover the message.

path_dec = ciphertext.copy()

for move in reversed(sk):
    inv_move = {
        'a': move['c'], 'b': move['d'],
        'c': move['a'], 'd': move['b'],
        'edge': move['new_edge'],
        'tri1': move['new_tri1'],
        'tri2': move['new_tri2'],
        'new_edge': move['edge'],
        'new_tri1': move['tri1'],
        'new_tri2': move['tri2']
    }
    path_dec = apply_2_2_move_to_path(path_dec, inv_move)

recovered_message = path_dec
print('Bob recovers plaintext: ', len(recovered_message), 'vertices')
print('Match original? ', recovered_message == message_path)

#---------------------------------------------------------------
# Security Analysis (Attacker's Perspective):
# An attacker sees the ciphertext and the scrambled torus.
# To decrypt, the attacker must find the shared secret sequence.
#
# Search space analysis:
#   - Valid moves per step: ~300 (for 10x10 grid)
#   - NUM_MOVES = 500
#   - Search space: 300^500 ≈ 10^1249 ≈ 2^4150
#
# This exceeds 128-bit and 256-bit security standards by a
# large margin. No known classical or quantum algorithm can
# solve the Secret Pachner Path Problem efficiently.
#---------------------------------------------------------------

# A sample of the execution results:
# Scrambled Torus:   100 V, 300 E, 200 T
# Shared secret:     500 Pachner moves
# Alice plaintext (cycle):  11 vertices
# Alice sends ciphertext:   89 vertices
# Bob recovers plaintext:   11 vertices
# Match original?  True

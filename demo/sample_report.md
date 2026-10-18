# AuditGraph report

_Generated 2026-10-18T16:12:49+00:00 from FalkorDB graph state._

**Confirmed:** 5  |  **Dismissed:** 1  |  **Unverified candidates:** 0  |  **Resolved by upgrade:** 1

## Confirmed findings

### [Critical] Unguarded call path reaches a privileged write — `Wallet.initialize()->Wallet._setAdmin(address)`

- **Finding id:** `AG-2f748b`  |  **SWC:** SWC-105/SWC-106  |  **Risk (PageRank):** 0.0400
- **Verdict:** Pattern missing_access_control_path holds on the graph evidence.
- **Verifier reasoning:** [mock verifier] Call path initialize -> _setAdmin reaches a write of privileged `admin` with no guarded function on the path.

**Graph evidence:**

- call path: `initialize -> _setAdmin` -[:WRITES {seq:1}]-> `admin` (no guard on any node)

**Cypher query that proves it:**

```cypher
MATCH p = (entry:Function)-[:CALLS*1..6]->(writer:Function),
      (writer)-[w:WRITES]->(s:StateVar {privileged: true})
WHERE entry.visibility IN ['public', 'external']
  AND none(n IN nodes(p) WHERE n.guarded)             // no guard anywhere on the path
  AND ($scope IS NULL OR any(n IN nodes(p) WHERE n.id IN $scope))
WITH entry, writer, s, w, p ORDER BY length(p)
WITH entry, writer, s, w, collect(p)[0] AS shortest
RETURN entry.id + '->' + writer.id AS fn, [n IN nodes(shortest) | n.id] AS path,
       [{write: s.name, write_seq: w.seq, via: [n IN nodes(shortest) | n.name]}] AS evidence
```

**Seen before in:**

- Poly Network (2021): A cross-chain message was crafted to call a privileged function and replace the keeper, letting the attacker authorise withdrawals; ~$600M moved (later returned).
- Parity Multisig (July) (2017): The wallet's initialisation function was reachable by anyone through the shared library (delegatecall), so an attacker re-initialised wallets and became owner; ~150k ETH stolen.

**Suggested fix:** Guard the public entry point, or move the access check into the internal function that performs the privileged write.

### [Critical] Unguarded entry point writes a privileged variable — `Wallet.setOwner(address)`

- **Finding id:** `AG-29ab22`  |  **SWC:** SWC-105/SWC-106  |  **Risk (PageRank):** 0.0148
- **Verdict:** Pattern missing_access_control_direct holds on the graph evidence.
- **Verifier reasoning:** [mock verifier] Unguarded entry point Wallet.setOwner(address) writes privileged `owner`.

**Graph evidence:**

- `-[:WRITES {seq:1}]-> owner` (privileged) from an unguarded entry point

**Cypher query that proves it:**

```cypher
MATCH (f:Function)-[w:WRITES]->(s:StateVar {privileged: true})
WHERE f.visibility IN ['public', 'external'] AND NOT f.guarded
  AND ($scope IS NULL OR f.id IN $scope)
RETURN f.id AS fn, [f.id] AS path,
       collect(DISTINCT {write: s.name, write_seq: w.seq}) AS evidence
```

**Seen before in:**

- Rubixi (2016): After a rename, the old constructor-named function became a public function, so anyone could call it and set themselves as owner.
- Parity Library Freeze (November) (2017): Anyone could initialise the library contract itself; a user became its owner and self-destructed it, freezing ~500k ETH in dependent wallets.
- Parity Multisig (July) (2017): The wallet's initialisation function was reachable by anyone through the shared library (delegatecall), so an attacker re-initialised wallets and became owner; ~150k ETH stolen.

**Suggested fix:** Restrict the function with an access-control modifier (e.g. onlyOwner) or an explicit require(msg.sender == owner).

### [High] Reentrancy: external call before state write — `VulnBank.withdrawAll()`

- **Finding id:** `AG-c4d4fc`  |  **SWC:** SWC-107  |  **Risk (PageRank):** 0.0148
- **Verdict:** Pattern reentrancy holds on the graph evidence.
- **Verifier reasoning:** [mock verifier] In VulnBank.withdrawAll(), the external `call` (seq 2) executes before `balances` is written (seq 5) and no reentrancy guard is attached.

**Graph evidence:**

- `-[:MAKES {seq:2}]-> call` (line 38) happens before `-[:WRITES {seq:5}]-> balances`

**Cypher query that proves it:**

```cypher
MATCH (f:Function)-[m:MAKES]->(e:ExternalCall), (f)-[w:WRITES]->(s:StateVar)
WHERE f.visibility IN ['public', 'external']
  AND m.seq < w.seq                                   // call BEFORE write
  AND NOT e.method IN ['send', 'transfer']            // 2300-gas stipend cannot re-enter
  AND NOT (f)-[:HAS_MODIFIER]->(:Modifier {is_reentrancy_guard: true})
  AND ($scope IS NULL OR f.id IN $scope)
RETURN f.id AS fn, [f.id] AS path,
       collect(DISTINCT {call: e.method, call_seq: m.seq, line: e.line,
                         write: s.name, write_seq: w.seq}) AS evidence
```

**Seen before in:**

- Lendf.Me (dForce) (2020): Reentrancy via ERC777 (imBTC) transfer hooks let the attacker inflate collateral; ~$25M taken (later returned).
- The DAO (2016): Reentrancy in the split function let the attacker withdraw repeatedly before balances were updated; ~3.6M ETH drained, leading to the Ethereum/Ethereum Classic hard fork.

**Suggested fix:** Apply checks-effects-interactions (update state before the external call) and/or add a nonReentrant guard (e.g. OpenZeppelin ReentrancyGuard).

### [Medium] Return value of low-level call is not checked — `UncheckedSend.withdraw()`

- **Finding id:** `AG-63c9fa`  |  **SWC:** SWC-104  |  **Risk (PageRank):** 0.0148
- **Verdict:** Pattern unchecked_low_level_call holds on the graph evidence.
- **Verifier reasoning:** [mock verifier] In UncheckedSend.withdraw(), the success flag of `call` (seq 3) is never read.

**Graph evidence:**

- `-[:MAKES {seq:3}]-> call` (line 27), checked = false

**Cypher query that proves it:**

```cypher
MATCH (f:Function)-[m:MAKES]->(e:ExternalCall {kind: 'low_level', checked: false})
WHERE ($scope IS NULL OR f.id IN $scope)
RETURN f.id AS fn, [f.id] AS path,
       collect(DISTINCT {call: e.method, call_seq: m.seq, line: e.line}) AS evidence
```

**Seen before in:**

- King of the Ether Throne (2016): Payments via send() to contract wallets failed for lack of gas and the failure was not checked, so ether was not delivered while the game continued.

**Suggested fix:** Capture and check the success flag: (bool ok, ) = to.call{...}(""); require(ok);

### [Medium] Return value of low-level call is not checked — `UncheckedSend.payout(address,uint256)`

- **Finding id:** `AG-cd0960`  |  **SWC:** SWC-104  |  **Risk (PageRank):** 0.0148
- **Verdict:** Pattern unchecked_low_level_call holds on the graph evidence.
- **Verifier reasoning:** [mock verifier] In UncheckedSend.payout(address,uint256), the success flag of `send` (seq 2) is never read.

**Graph evidence:**

- `-[:MAKES {seq:2}]-> send` (line 32), checked = false

**Cypher query that proves it:**

```cypher
MATCH (f:Function)-[m:MAKES]->(e:ExternalCall {kind: 'low_level', checked: false})
WHERE ($scope IS NULL OR f.id IN $scope)
RETURN f.id AS fn, [f.id] AS path,
       collect(DISTINCT {call: e.method, call_seq: m.seq, line: e.line}) AS evidence
```

**Seen before in:**

- King of the Ether Throne (2016): Payments via send() to contract wallets failed for lack of gas and the failure was not checked, so ether was not delivered while the game continued.

**Suggested fix:** Capture and check the success flag: (bool ok, ) = to.call{...}(""); require(ok);

## Dismissed findings

- `AG-8d7038` reentrancy:VulnBank.sweepFees() — treasury is an immutable, trusted multisig set at deploy; cannot re-enter

## Resolved by upgrade

- `AG-656659` reentrancy:VulnBank.withdraw(uint256) (no longer matches in v2)

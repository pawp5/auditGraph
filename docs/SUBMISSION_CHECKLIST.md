# Submission checklist (deadline: Oct 18, 23:59 IST)

- [ ] Create a public GitHub repo and push all commits (`git remote add origin … && git push -u origin main`)
- [ ] `docker compose up -d` + run README "Run" section on a clean clone
- [ ] `python -m pytest -q` → 10 passed
- [ ] (Optional) one live LLM audit: `export ANTHROPIC_API_KEY=… LLM_MODEL=…; python -m src.main audit --full`
- [ ] Record demo video following `demo/script.md` (3–4 min), upload, and put the link in the README
- [ ] Regenerate `demo/sample_report.md` if you ran the live LLM
- [ ] Submission form: repo URL, video URL, tracks = "Agents That Act on Connected Data" (primary) + "Agent Memory and Coordination"
- [ ] Point judges to: README "Why the graph is essential", `src/queries.py`, `docs/EXPLAIN.md`
- [ ] Confirm no secrets: `git grep -i "sk-ant"` returns nothing; `.env` is not committed
- [ ] AI-assistance disclosure section present in the README

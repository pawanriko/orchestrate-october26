# Orchestrate October'26

24-hour AI agent hackathon entry — HackerRank Orchestrate October'26.

**Window:** Sat Oct 24, 2026 6:00 PM IST → Sun Oct 25, 2026 6:00 PM IST
**Challenge page:** https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges
**Discord:** https://discord.gg/TzsUaAhPbr

## Timeline
- Challenge arrives by email: Oct 24, 6:00 PM IST
- Submission deadline: Oct 25, 6:00 PM IST
- AI judge interview: opens on submit, closes Oct 26, 6:00 AM IST
- Results: Oct 27, 6:00 PM IST

## Strategy (from September edition learnings)
- Deterministic, plain-rules core first — scores reward consistent, correct answers over "throw the model at it"
- Keep the deterministic core inspectable / easy to explain
- The AI chat transcript is part of the submission — keep build chats deliberate
- Practice explaining architecture, decisions, and tradeoffs out loud for the 30-min AI-judge interview

## Structure
- `src/` — agent code (problem statement drops Oct 24, 6:00 PM IST)
- `docs/` — architecture notes and decision log for the judge interview
- `tests/` — checks for the deterministic core

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

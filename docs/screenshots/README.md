# Screenshots

Add PNG screenshots of the GUI here. The main `README.md` already references
these filenames, so name the files exactly as listed below and they will show
up automatically.

To produce a clean, neutral demo to capture, run first:

```bash
python scripts/gen_demo.py --fresh
python -m secure_vault.gui
```

Capture these views:

| Filename | View | What to show |
|----------|------|--------------|
| `dashboard.png` | **Dashboard** tab | The statistic cards (Certificates / Users / Files / Encrypted) and the activity log. |
| `setup.png` | **Setup** tab | The one-click "Initialize System" panel and a completed setup log. |
| `server.png` | **Server** tab | Server status "Online" and the registered users list (user1 / user2). |
| `client-store.png` | **Client → Store File** | A sample file selected, ready to "Encrypt & Store". |
| `client-verify.png` | **Client → Retrieve Files** | A stored file selected with an "integrity verified" result dialog. |

Keep every screenshot free of personal data — the demo entities are the
neutral `vault`, `user1` and `user2`.

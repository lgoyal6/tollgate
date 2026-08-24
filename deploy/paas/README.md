# One-click and CLI deploy targets

The Render blueprint lives at the **repository root** (`../../render.yaml`), not
here: Render's Deploy to Render button only looks for `render.yaml` at the root
of a repo and will not find one in a subdirectory.

What is here:

| File | What it is | Gives you a button? |
|---|---|---|
| `fly.toml` | Full Fly.io app config | No. Fly has no one-click button; it is `fly launch` from a shell. |
| `railway.json` | Railway build and deploy config | No. Railway's button is `railway.com/new/template/<code>`, which requires publishing a template from Railway's dashboard first. This file configures the service once the project exists. |

So the button in the README is Render's, and it is the only true one-click path
of the three. The other two are short CLI sequences, documented in each file.

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

## Deploying the demo upstream too

The gateway is only half a deploy: every route needs something to proxy to.
`Dockerfile.upstream` exists for that. The main Dockerfile builds the upstream
as a named stage, and a PaaS builds whatever stage is last with no way to pick
one, so the demo backend needs a file whose default stage is the upstream.

On Railway that is a second service in the same project with
`RAILWAY_DOCKERFILE_PATH=Dockerfile.upstream`, reachable from the gateway over
the private network at `http://upstream.railway.internal:9000`. Render and Fly
take the same file through `dockerfilePath` and `build.dockerfile`.

The gateway itself needs `AUTO_MIGRATE=true` on any of the three: the image is
distroless and nothing else in the container can apply a migration.

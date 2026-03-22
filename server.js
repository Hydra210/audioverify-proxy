const express = require("express")
const fetch   = require("node-fetch")

// ============================================================
//                          CFG
// ============================================================

const PROXY_SECRET = process.env.PROXY_SECRET
const PERMS_BASE   = "https://apis.roblox.com/asset-permissions-api/v1/assets"
const ECONOMY_BASE = "https://economy.roblox.com/v2/assets"

// ============================================================
//                         HELPERS
// ============================================================

const app = express()
app.use(express.json())

function authed(req, res) {
	if (req.headers["x-proxy-secret"] !== PROXY_SECRET) {
		console.log("[auth] forbidden — bad or missing secret")
		res.status(403).json({ error: "forbidden" })
		return false
	}
	return true
}

// per-request cookie — bot sends it via header, falls back to env
function getCookie(req) {
	return req.headers["x-cookie-override"] || process.env.ROBLOSECURITY || ""
}

async function getCsrf(cookie) {
	const r = await fetch("https://auth.roblox.com/v2/logout", {
		method:  "POST",
		headers: { Cookie: `.ROBLOSECURITY=${cookie}` },
	}).catch(e => { console.log("[csrf] error:", e.message); return null })

	const token = r ? r.headers.get("x-csrf-token") : null
	console.log("[csrf]", token ? "got token" : "FAILED")
	return token
}

async function robloxGet(url) {
	let r = await fetch(url).catch(e => { console.log("[get] error:", e.message); return null })
	if (r && r.status === 429) {
		console.log("[get] rate limited — retrying in 2s")
		await new Promise(res => setTimeout(res, 2000))
		r = await fetch(url).catch(() => null)
	}
	return r
}

// ============================================================
//                          ROUTES
// ============================================================

// asset info — used by /verify to show name, creator, description
app.get("/asset/:id", async (req, res) => {
	if (!authed(req, res)) return

	const url = `${ECONOMY_BASE}/${req.params.id}/details`
	console.log("[asset] fetching:", url)

	const r = await robloxGet(url)
	if (!r) return res.status(502).json({ error: "upstream failed" })

	console.log("[asset] status:", r.status)
	const body = await r.json().catch(() => ({}))
	res.status(r.status).json(body)
})

// grant universe permission on an audio asset
app.patch("/asset/:id/permissions", async (req, res) => {
	if (!authed(req, res)) return

	const assetId    = req.params.id
	const subjectId  = req.body.subjectId
	const cookie     = getCookie(req)

	if (!subjectId) return res.status(400).json({ error: "missing subjectId" })
	if (!cookie)    return res.status(400).json({ error: "no cookie available" })

	const payload = {
		requests:              [{ subjectType: "Universe", subjectId: String(subjectId), action: "Use" }],
		grantToDependencies:   true,
		enableDeepAccessCheck: false,
	}

	const url = `${PERMS_BASE}/${assetId}/permissions`
	console.log("[perms] PATCH", url)
	console.log("[perms] subjectId:", subjectId)

	const csrf = await getCsrf(cookie)
	if (!csrf) return res.status(502).json({ error: "could not get csrf token" })

	const r = await fetch(url, {
		method:  "PATCH",
		headers: {
			"Content-Type": "application/json",
			"Cookie":        `.ROBLOSECURITY=${cookie}`,
			"x-csrf-token":  csrf,
		},
		body: JSON.stringify(payload),
	}).catch(e => { console.log("[perms] error:", e.message); return null })

	if (!r) return res.status(502).json({ error: "upstream failed" })

	console.log("[perms] status:", r.status)
	const body = await r.json().catch(() => ({}))
	res.status(r.status).json(body)
})

// health / ping
app.get("/ping", (_, res) => res.send("ok"))
app.get("/",     (_, res) => res.send("AudioVerify proxy is running."))

// ============================================================
//                          ENTRY
// ============================================================

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`proxy up on :${PORT}`))

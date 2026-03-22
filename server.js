const express = require("express")
const fetch   = require("node-fetch")
const app = express()
app.use(express.json())

const PROXY_SECRET = process.env.PROXY_SECRET
const PERMS_BASE   = "https://apis.roblox.com/asset-permissions-api/v1/assets"
const ECONOMY_BASE = "https://economy.roblox.com/v2/assets"

function authed(req, res) {
	if (req.headers["x-proxy-secret"] !== PROXY_SECRET) {
		console.log("[auth] forbidden — bad or missing proxy secret")
		res.status(403).json({ error: "forbidden" })
		return false
	}
	return true
}

// uses x-cookie-override header if provided, otherwise falls back to env
function getCookie(req) {
	return req.headers["x-cookie-override"] || process.env.ROBLOSECURITY || ""
}

async function getCsrf(cookie) {
	const r = await fetch("https://auth.roblox.com/v2/logout", {
		method:  "POST",
		headers: { "Cookie": `.ROBLOSECURITY=${cookie}` },
	}).catch(e => { console.log("[csrf] fetch error:", e.message); return null })
	const token = r ? r.headers.get("x-csrf-token") : null
	console.log("[csrf] token:", token ? "got it" : "FAILED")
	return token
}

app.get("/asset/:id", async (req, res) => {
	if (!authed(req, res)) return
	const url = `${ECONOMY_BASE}/${req.params.id}/details`
	console.log("[get asset] fetching:", url)
	let r = await fetch(url).catch(e => { console.log("[get asset] error:", e.message); return null })
	if (r && r.status === 429) {
		console.log("[get asset] rate limited, retrying in 2s")
		await new Promise(res => setTimeout(res, 2000))
		r = await fetch(url).catch(() => null)
	}
	if (!r) return res.status(502).json({ error: "upstream failed" })
	console.log("[get asset] status:", r.status)
	const body = await r.json().catch(() => ({}))
	console.log("[get asset] body:", JSON.stringify(body).slice(0, 300))
	res.status(r.status).json(body)
})

app.patch("/asset/:id/permissions", async (req, res) => {
	if (!authed(req, res)) return
	const assetId   = req.params.id
	const subjectId = req.body.subjectId
	const cookie    = getCookie(req)
	const url       = `${PERMS_BASE}/${assetId}/permissions`
	const payload   = {
		requests:              [{ subjectType: "Universe", subjectId: subjectId, action: "Use" }],
		grantToDependencies:   true,
		enableDeepAccessCheck: false,
	}
	console.log("[patch perms] fetching:", url)
	console.log("[patch perms] body:", JSON.stringify(payload))
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
	}).catch(e => { console.log("[patch perms] error:", e.message); return null })
	if (!r) return res.status(502).json({ error: "upstream failed" })
	console.log("[patch perms] status:", r.status)
	const body = await r.json().catch(() => ({}))
	console.log("[patch perms] body:", JSON.stringify(body).slice(0, 300))
	res.status(r.status).json(body)
})

// fetch authenticated roblox profile for a given cookie
app.get("/me", async (req, res) => {
	if (!authed(req, res)) return
	const cookie = getCookie(req)
	if (!cookie) return res.status(400).json({ error: "no cookie" })
	const r = await fetch("https://users.roblox.com/v1/users/authenticated", {
		headers: { Cookie: `.ROBLOSECURITY=${cookie}` },
	}).catch(e => { console.log("[me] error:", e.message); return null })
	if (!r) return res.status(502).json({ error: "upstream failed" })
	console.log("[me] status:", r.status)
	const body = await r.json().catch(() => ({}))
	res.status(r.status).json(body)
})

app.get("/ping", (_, res) => res.send("ok"))
app.get("/",     (_, res) => res.send("AudioVerify proxy is running."))
app.listen(process.env.PORT || 3000, () => console.log("proxy up"))

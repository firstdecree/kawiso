(async () => {
    "use strict";

    // Dependencies
    const client = await require("./modules/mongodb.js")
    const simpleAES256 = require("simple-aes-256")
    const cookieParser = require("cookie-parser")
    const compression = require("compression")
    const UAParser = require("ua-parser-js")
    const requestIP = require("request-ip")
    const { parse } = require("smol-toml")
    const express = require("express")
    const hashJS = require("hash.js")
    const cryptr = require("cryptr")
    const helmet = require("helmet")
    const crypto = require("crypto")
    const axios = require("axios")
    const path = require("path")
    const fs = require("fs")

    // Variables
    const config = parse(fs.readFileSync("./config.toml", "utf8"))
    const cT = new cryptr(config.security.cookieMasterKey, {
        encoding: config.security.cookieEncoding,
        pbkdf2Iterations: config.security.cookiePBKDF2Iterations,
        saltLength: config.security.cookieSaltLength
    })
    const web = express()

    const database = client.db(config.database.database)
    const users = database.collection(config.database.usersCollection)
    const analyticsData = database.collection(config.database.analyticsDataCollection)

    // Functions
    const SHA512 = (string) => hashJS.sha512().update(string).digest("hex")
    const setCookie = (res, data) => {
        res.cookie("d", data, {
            maxAge: 12 * 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === "production"
        })
    }
    const dS = async (session) => {
        try { return JSON.parse(cT.decrypt(session.d)) }
        catch { return false }
    }

    const sAES256E = (password, string) => simpleAES256.encrypt(password, string).toString("hex")
    const sAES256D = (password, string) => simpleAES256.decrypt(password, Buffer.from(string, "hex")).toString("utf8")

    const generateUUID = () => {
        // Variables
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        const lengths = [8, 8, 8, 8]

        // Core
        return lengths.map((len) => {
            const bytes = crypto.randomBytes(len)
            var part = ""

            for (let i = 0; i < len; i++) part += chars[bytes[i] % chars.length]
            return part
        }).join("-")
    }

    const requireAuth = async (req, res, next) => {
        // Variables
        const userData = await dS(req.cookies)

        // Validations
        if (!userData) return res.redirect("/login")

        // Core
        req._user = userData
        next()
    }

    const getBasicStats = async (hashedUsername, startDate, endDate, domain) => {
        // Variables
        const match = {
            hashedUsername,
            ts: { $gte: startDate.getTime(), $lte: endDate.getTime() }
        }

        if (domain) match.domain = domain
        const hits = await analyticsData.find(match).toArray()
        if (hits.length === 0) return { totalVisits: 0, uniqueUsers: 0, avgDuration: 0, bounceRate: 0 }

        // Core
        const totalVisits = hits.length
        const uniqueUsers = new Set(hits.map(h => h.fingerprint)).size
        const fpGroups = {}
        hits.forEach(h => {
            if (!fpGroups[h.fingerprint]) fpGroups[h.fingerprint] = []
            fpGroups[h.fingerprint].push(h.ts)
        })

        var bounces = 0
        const durations = Object.values(fpGroups).map(times => {
            if (times.length < 2) {
                bounces++
                return 0
            }
            times.sort((a, b) => a - b)
            return times[times.length - 1] - times[0]
        }).filter(d => d > 0 && d < 3600000)

        var avgDuration = 0
        if (durations.length > 0) avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length
        const bounceRate = uniqueUsers > 0 ? Math.round((bounces / uniqueUsers) * 100) : 0
        return { totalVisits, uniqueUsers, avgDuration, bounceRate }
    }

    const getAnalytics = async (hashedUsername, startDate, endDate, domain) => {
        // Variables
        const match = {
            hashedUsername,
            ts: { $gte: startDate.getTime(), $lte: endDate.getTime() }
        }
        if (domain) match.domain = domain
        const hits = await analyticsData.find(match).toArray()
        if (hits.length === 0) return null

        const periodMs = endDate.getTime() - startDate.getTime()
        const prevStart = new Date(startDate.getTime() - periodMs)
        const prevEnd = new Date(endDate.getTime() - periodMs)

        const totalVisits = hits.length
        const uniqueUsers = new Set(hits.map(h => h.fingerprint)).size
        const dailyMap = {}
        const dailyUsersMap = {}
        hits.forEach(h => {
            const day = new Date(h.ts).toLocaleDateString("en-US", { month: "short", day: "numeric" })
            dailyMap[day] = (dailyMap[day] || 0) + 1
            if (!dailyUsersMap[day]) dailyUsersMap[day] = new Set()
            dailyUsersMap[day].add(h.fingerprint)
        })
        const labels = []
        const visitArr = []
        const userArr = []
        const cursor = new Date(startDate)
        cursor.setHours(0, 0, 0, 0)

        // Core
        while (cursor <= endDate) {
            const label = cursor.toLocaleDateString("en-US", { month: "short", day: "numeric" })
            labels.push(label)
            visitArr.push(dailyMap[label] || 0)
            userArr.push(dailyUsersMap[label] ? dailyUsersMap[label].size : 0)
            cursor.setDate(cursor.getDate() + 1)
        }
        const refTypeCounts = {}
        hits.forEach(h => { refTypeCounts[h.refType || "direct"] = (refTypeCounts[h.refType || "direct"] || 0) + 1 })
        const sources = [
            { icon: "🔍", name: "Search Engines", key: "search" },
            { icon: "🔗", name: "Direct", key: "direct" },
            { icon: "📣", name: "Social Networks", key: "social" },
            { icon: "↗️", name: "Referrers", key: "referral" },
        ].map(s => ({ ...s, count: refTypeCounts[s.key] || 0, pct: Math.round((refTypeCounts[s.key] || 0) / totalVisits * 100) }))
            .filter(s => s.count > 0)
            .sort((a, b) => b.count - a.count)
        const pageMap = {}
        const prevPageMap = {}
        hits.forEach(h => { pageMap[h.path] = (pageMap[h.path] || 0) + 1 })

        const prevHits = await analyticsData.find({
            hashedUsername,
            ts: { $gte: prevStart.getTime(), $lte: prevEnd.getTime() },
            ...(domain ? { domain } : {})
        }).toArray()

        prevHits.forEach(h => { prevPageMap[h.path] = (prevPageMap[h.path] || 0) + 1 })

        const pages = Object.entries(pageMap)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([path, count]) => {
            const prevCount = prevPageMap[path] || 0
            var trend = "0%"
            var isUp = true

            if (prevCount === 0) {
                trend = "New"
                isUp = true
            } else {
                const delta = Math.round(((count - prevCount) / prevCount) * 100)
                trend = (delta > 0 ? "+" : "") + delta + "%"
                isUp = delta >= 0
            }

            return { path, visits: count, trend, isUp }
        })

        const browserMap = {}
        hits.forEach(h => {
            const ua = new UAParser(h.ua || "").getBrowser().name || "Other"
            browserMap[ua] = (browserMap[ua] || 0) + 1
        })

        const platformMap = {}
        hits.forEach(h => {
            const os = new UAParser(h.ua || "").getOS().name || "Other"
            platformMap[os] = (platformMap[os] || 0) + 1
        })

        const deviceMap = {}
        hits.forEach(h => {
            const type = new UAParser(h.ua || "").getDevice().type || "desktop"
            const label = type.charAt(0).toUpperCase() + type.slice(1)
            deviceMap[label] = (deviceMap[label] || 0) + 1
        })

        const langMap = {}
        hits.forEach(h => { langMap[h.language || "Unknown"] = (langMap[h.language || "Unknown"] || 0) + 1 })
        const screenMap = {}
        hits.forEach(h => { screenMap[h.screen || "Unknown"] = (screenMap[h.screen || "Unknown"] || 0) + 1 })
        const timeMap = { morning: 0, afternoon: 0, evening: 0, night: 0 }
        hits.forEach(h => { if (timeMap.hasOwnProperty(h.timeOfDay)) timeMap[h.timeOfDay]++ })
        const hourlyMap = Array(24).fill(0)
        hits.forEach(h => {
            const hr = new Date(h.ts).getHours()
            hourlyMap[hr]++
        })

        const countryMap = {}
        hits.forEach(h => {
            const c = h.country || "Unknown"
            if (!countryMap[c]) countryMap[c] = { count: 0, flag: h.flag || "🌐" }
            countryMap[c].count++
        })

        const tzMap = {}
        hits.forEach(h => {
            const tz = h.timezone || "Unknown"
            tzMap[tz] = (tzMap[tz] || 0) + 1
        })

        const toDistArray = (map) => {
            const total = Object.values(map).reduce((a, b) => a + b, 0) || 1
            return Object.entries(map)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 6)
                .map(([label, count]) => ({ label, count, pct: Math.round(count / total * 100) }))
        }

        var avgDuration = 0
        const fpGroups = {}
        hits.forEach(h => {
            if (!fpGroups[h.fingerprint]) fpGroups[h.fingerprint] = []
            fpGroups[h.fingerprint].push(h.ts)
        })

        var bounces = 0
        const durations = Object.values(fpGroups).map(times => {
            if (times.length < 2) {
                bounces++
                return 0
            }
            times.sort((a, b) => a - b)
            return times[times.length - 1] - times[0]
        }).filter(d => d > 0 && d < 3600000)
        if (durations.length > 0) avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length

        const bounceRate = uniqueUsers > 0 ? Math.round((bounces / uniqueUsers) * 100) : 0
        const fmtDuration = (ms) => {
            const s = Math.round(ms / 1000)
            return `${Math.floor(s / 60)}m ${s % 60}s`
        }

        const prevStats = await getBasicStats(hashedUsername, prevStart, prevEnd, domain)
        const calcDelta = (curr, prev) => {
            if (prev === 0) return curr > 0 ? "New" : 0
            return Math.round(((curr - prev) / prev) * 100)
        }

        const deltas = {
            visitsDelta: calcDelta(totalVisits, prevStats.totalVisits),
            usersDelta: calcDelta(uniqueUsers, prevStats.uniqueUsers),
            durationDelta: calcDelta(avgDuration, prevStats.avgDuration),
            bounceDelta: calcDelta(bounceRate, prevStats.bounceRate)
        }

        return {
            totalVisits,
            uniqueUsers,
            bounceRate,
            avgDuration: fmtDuration(avgDuration),
            deltas,
            chartLabels: labels,
            visitArr,
            userArr,
            sources,
            pages,
            browsers: toDistArray(browserMap),
            platforms: toDistArray(platformMap),
            devices: toDistArray(deviceMap),
            languages: toDistArray(langMap),
            screens: toDistArray(screenMap),
            timeOfDay: timeMap,
            hourly: hourlyMap,
            countries: Object.entries(countryMap).sort((a, b) => b[1].count - a[1].count).slice(0, 10).map(([name, data]) => ({ name, count: data.count, flag: data.flag })),
            timezones: Object.entries(tzMap).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ name, count }))
        }
    }

    // Configurations
    //* Express
    web.use(compression({ level: 1 }))
    web.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: "cross-origin" } }))
    web.use(cookieParser())
    web.set("view engine", "ejs")
    web.set("views", path.join(__dirname, "views"))
    web.use(express.json())
    web.use((req, res, next) => {
        // Validations
        if (req.path.endsWith(".html")) return res.redirect(req.path.replace(/.html$/, ""))

        // Core
        next()
    })

    // Main
    web.get("/login", async (req, res, next) => {
        // Variables
        const userData = await dS(req.cookies)

        // Validations
        if (userData) return res.redirect("/dashboard")

        // Core
        next()
    })

    web.get("/register", async (req, res, next) => {
        // Variables
        const userData = await dS(req.cookies)

        // Validations
        if (userData) return res.redirect("/dashboard")

        // Core
        next()
    })
    web.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }))

    web.post("/api/login", async (req, res) => {
        const userData = await dS(req.cookies)
        if (userData) return res.send("1")

        // Variables
        const { username, password } = req.body
        const accountData = await users.findOne({
            hashedUsername: SHA512(username),
            password: SHA512(password)
        })

        // Validations
        if (!accountData) return res.send("0")

        // Core
        setCookie(res, cT.encrypt(JSON.stringify({
            username: sAES256D(password, accountData.username),
            uuid: accountData.uuid,
            hashedUsername: accountData.hashedUsername
        })))
        res.send("1")
    })

    web.post("/api/register", async (req, res) => {
        const userData = await dS(req.cookies)
        if (userData) return res.send("1")

        // Variables
        const { username, password } = req.body
        const accountData = await users.findOne({ hashedUsername: SHA512(username) })

        // Variables
        if (accountData) return res.send("0")

        // Core
        if (config.production.allowRegistration) {
            await users.insertOne({
                hashedUsername: SHA512(username),
                username: sAES256E(password, username),
                password: SHA512(password),
                uuid: generateUUID(),
                plan: "analyst",
                settings: {
                    whitelistedDomains: []
                }
            })
        }

        res.send("1")
    })

    web.get("/api/logout", (req, res) => { res.clearCookie("d").redirect("/login") })
    web.post("/collect", async (req, res) => {
        // Variables
        const { id, path: hitPath, referrer, refType, language, screen, timeOfDay, fingerprint, ts, timezone } = req.body
        if (!id) return res.status(400).end()
        const user = await users.findOne({ uuid: id })
        if (!user) return res.status(404).end()

        const originHeader = req.headers["origin"] || ""
        var domain = "unknown"

        try {
            if (originHeader) domain = new URL(originHeader).hostname
        } catch { }

        const whitelistedDomains = (user.settings && user.settings.whitelistedDomains) || []
        if (!whitelistedDomains.includes(domain)) {
            const originStr = req.headers["origin"] || "*"
            res.setHeader("Access-Control-Allow-Origin", originStr)
            res.setHeader("Access-Control-Allow-Credentials", "false")
            res.setHeader("Vary", "Origin")
            return res.status(204).end()
        }

        const ua = req.headers["user-agent"] || ""
        var browser = new UAParser(ua).getBrowser().name || "Other"
        const secChUa = req.headers["sec-ch-ua"] || ""

        if (secChUa.toLowerCase().includes("brave") || ua.toLowerCase().includes("brave")) {
            browser = "Brave"
        } else if (secChUa.toLowerCase().includes("firefox") || ua.toLowerCase().includes("firefox")) {
            browser = "Firefox"
        }
        const os = new UAParser(ua).getOS().name || "Other"
        const device = new UAParser(ua).getDevice().type || "desktop"

        const ip = requestIP.getClientIp(req) || ""
        if (ip.startsWith("::ffff:")) ip = ip.substring(7)

        // Core
        const targetIp = (ip && ip !== "127.0.0.1" && ip !== "::1") ? ip : ""
        var country = "Unknown"
        var flag = "🌐"
        var timeOfD = timeOfDay || "unknown"
        var timezoneStr = timezone || "Unknown"

        if (targetIp) {
            try {
                const resp = (await axios.get(`https://ipwho.is/${targetIp}`, {
                    headers: {
                        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                        "accept-language": "en-US,en;q=0.5",
                        "cache-control": "max-age=0",
                        dnt: "1",
                        priority: "u=0, i",
                        "sec-ch-ua": `"Not:A-Brand";v="99", "Brave";v="145", "Chromium";v="145"`,
                        "sec-ch-ua-mobile": "?0",
                        "sec-ch-ua-platform": `"Linux"`,
                        "sec-fetch-dest": "document",
                        "sec-fetch-mode": "navigate",
                        "sec-fetch-site": "none",
                        "sec-fetch-user": "?1",
                        "sec-gpc": "1",
                        "upgrade-insecure-requests": "1",
                        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
                    },
                    timeout: 2500
                })).data

                if (resp.success) {
                    country = resp.country || country

                    if (resp.flag && resp.flag.emoji) flag = resp.flag.emoji
                    if (resp.timezone && resp.timezone.id) {
                        if (timezoneStr === "Unknown") timezoneStr = resp.timezone.id;
                        try {
                            const hr = parseInt(new Date().toLocaleString("en-US", { timeZone: resp.timezone.id, hour: 'numeric', hour12: false }), 10)
                            if (hr >= 6 && hr < 12) timeOfD = "morning"
                            else if (hr >= 12 && hr < 18) timeOfD = "afternoon"
                            else if (hr >= 18 && hr < 24) timeOfD = "evening"
                            else timeOfD = "night"
                        } catch { }
                    }
                }
            } catch { }
        }

        try {
            if (language && language !== "Unknown" && language.length >= 2) {
                const ln = new Intl.DisplayNames(['en'], { type: 'language' })
                language = ln.of(language.toLowerCase()) || language
            }
        } catch { }

        await analyticsData.insertOne({
            hashedUsername: user.hashedUsername,
            domain,
            path: hitPath || "/",
            referrer: referrer || null,
            refType: refType || "direct",
            language: language || "Unknown",
            screen: screen || "Unknown",
            timezone: timezoneStr,
            timeOfDay: timeOfD,
            country,
            flag,
            fingerprint: fingerprint || crypto.randomUUID(),
            browser,
            os,
            device,
            ua,
            ts: ts || Date.now()
        })

        const origin = req.headers["origin"] || "*"
        res.setHeader("Access-Control-Allow-Origin", origin)
        res.setHeader("Access-Control-Allow-Credentials", "false")
        res.setHeader("Vary", "Origin")
        res.end()
    })

    web.options("/collect", (req, res) => {
        // Variables
        const origin = req.headers["origin"] || "*"

        // Core
        res.setHeader("Access-Control-Allow-Origin", origin)
        res.setHeader("Access-Control-Allow-Credentials", "false")
        res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS")
        res.setHeader("Access-Control-Allow-Headers", "Content-Type")
        res.setHeader("Vary", "Origin")
        res.end()
    })

    web.get("/api/domains", requireAuth, async (req, res) => {
        // Variables
        const user = req._user
        const domains = await analyticsData.distinct("domain", {
            hashedUsername: user.hashedUsername
        })

        // Core
        res.json({ ok: true, domains: domains.filter(d => d && d !== "unknown") })
    })

    web.get("/api/analytics", requireAuth, async (req, res) => {
        // Variables
        const user = req._user
        const range = req.query.range || "1m"
        const domain = req.query.domain || null
        const now = new Date()
        var start = new Date()

        // Core
        if (range === "7d") start.setDate(now.getDate() - 7)
        else if (range === "1m") start.setMonth(now.getMonth() - 1)
        else if (range === "1y") start.setFullYear(now.getFullYear() - 1)
        else if (range === "custom") {
            const s = req.query.start
            const e = req.query.end
            if (!s || !e) return res.status(400).json({ error: "Need start and end" })
            start = new Date(s + "T00:00:00.000Z")
            now.setTime(new Date(e + "T23:59:59.999Z").getTime())
        } else { start.setMonth(now.getMonth() - 1) }

        const data = await getAnalytics(user.hashedUsername, start, now, domain)
        res.json({ ok: true, data })
    })

    web.get("/dashboard", requireAuth, async (req, res) => {
        const user = req._user
        // Variables
        const domains = await analyticsData.distinct("domain", {
            hashedUsername: user.hashedUsername
        }).then(d => d.filter(v => v && v !== "unknown"))
        const activeDomain = req.query.domain || domains[0] || null
        const userDoc = await users.findOne({ hashedUsername: user.hashedUsername }) || {}

        // Core
        res.render("dashboard", { user, domains, userDoc, activeDomain, req })
    })

    web.get("/map", requireAuth, async (req, res) => {
        // Variables
        const user = req._user
        const domains = await analyticsData.distinct("domain", { hashedUsername: user.hashedUsername }).then(d => d.filter(v => v && v !== "unknown"))
        const activeDomain = req.query.domain || domains[0] || null
        const now = new Date()
        const start = new Date()
        start.setMonth(now.getMonth() - 1)

        // Core
        const analytics = await getAnalytics(user.hashedUsername, start, now, activeDomain)
        const userDoc = await users.findOne({ hashedUsername: user.hashedUsername }) || {}
        res.render("map", { user, analytics, domains, userDoc, activeDomain, req })
    })

    web.get("/account-settings", requireAuth, async (req, res) => {
        // Variables
        const user = req._user
        const domains = await analyticsData.distinct("domain", { hashedUsername: user.hashedUsername }).then(d => d.filter(v => v && v !== "unknown"))
        const activeDomain = domains[0] || null

        // Core
        const userDoc = await users.findOne({ hashedUsername: user.hashedUsername }) || {}
        const whitelistedDomains = (userDoc.settings && userDoc.settings.whitelistedDomains) || []
        res.render("account-settings", { user, domains, activeDomain, userDoc, whitelistedDomains })
    })

    web.get("/pages", requireAuth, async (req, res) => {
        // Variables
        const user = req._user
        const domains = await analyticsData.distinct("domain", { hashedUsername: user.hashedUsername }).then((d) => d.filter(v => v && v !== "unknown"))
        const activeDomain = domains[0] || null

        // Core
        const userDoc = await users.findOne({ hashedUsername: user.hashedUsername }) || {}
        const whitelistedDomains = (userDoc.settings && userDoc.settings.whitelistedDomains) || []
        res.render("pages", { user, domains, activeDomain, userDoc, whitelistedDomains })
    })

    web.post("/api/settings/whitelisted-domains", requireAuth, async (req, res) => {
        // Variables
        const user = req._user
        const { domains } = req.body

        // Validations
        if (!Array.isArray(domains)) return res.status(400).json({ ok: false })
        if (domains.some((url) => !/^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}$/.test(url.split("/")[0]))) return res.status(400).json({ ok: false })
        await users.updateOne({ hashedUsername: user.hashedUsername }, { $set: { "settings.whitelistedDomains": domains } })

        // Main
        res.json({ ok: true })
    })

    web.post("/api/settings/purge-data", requireAuth, async (req, res) => {
        // Variables
        const user = req._user

        // Core
        await analyticsData.deleteMany({ hashedUsername: user.hashedUsername })
        res.json({ ok: true })
    })

    web.post("/api/settings/delete-account", requireAuth, async (req, res) => {
        // Variables
        const user = req._user

        // Core
        await analyticsData.deleteMany({ hashedUsername: user.hashedUsername })
        await users.deleteOne({ hashedUsername: user.hashedUsername })
        res.clearCookie("d").json({ ok: true })
    })

    web.get("/api/pages", requireAuth, async (req, res) => {
        // Variables
        const user = req._user
        const range = req.query.range || "1m"
        const domain = req.query.domain || null
        const now = new Date()
        var start = new Date()

        if (range === "7d") start.setDate(now.getDate() - 7)
        else if (range === "1m") start.setMonth(now.getMonth() - 1)
        else if (range === "1y") start.setFullYear(now.getFullYear() - 1)
        else start.setMonth(now.getMonth() - 1)

        // Core
        const match = {
            hashedUsername: user.hashedUsername,
            ts: { $gte: start.getTime(), $lte: now.getTime() }
        }
        if (domain) match.domain = domain

        const hits = await analyticsData.find(match).toArray()
        if (hits.length === 0) return res.json({ ok: true, pages: [] })

        const periodMs = now.getTime() - start.getTime()
        const prevStart = new Date(start.getTime() - periodMs)
        const prevEnd = new Date(start.getTime())

        const pageMap = {}
        const prevPageMap = {}
        hits.forEach(h => { pageMap[h.path] = (pageMap[h.path] || 0) + 1 })

        const prevHits = await analyticsData.find({
            hashedUsername: user.hashedUsername,
            ts: { $gte: prevStart.getTime(), $lte: prevEnd.getTime() },
            ...(domain ? { domain } : {})
        }).toArray()

        prevHits.forEach(h => { prevPageMap[h.path] = (prevPageMap[h.path] || 0) + 1 })

        const pages = Object.entries(pageMap)
            .map(([path, count]) => {
                const prevCount = prevPageMap[path] || 0
                var growth = 0

                if (prevCount === 0) {
                    growth = "New"
                } else {
                    growth = Math.round(((count - prevCount) / prevCount) * 100)
                }

                const pathHits = hits.filter(h => h.path === path).sort((a, b) => a.ts - b.ts)
                const dailyData = Array(7).fill(0)
                for (let i = 6; i >= 0; i--) {
                    const dayStart = new Date(now.getTime() - i * 24 * 60 * 60 * 1000)
                    dayStart.setHours(0, 0, 0, 0)
                    const dayEnd = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000)
                    const dayCount = pathHits.filter(h => h.ts >= dayStart.getTime() && h.ts < dayEnd.getTime()).length
                    dailyData[6 - i] = dayCount
                }

                return { path, visits: count, growth, sparkline: dailyData }
            })
            .sort((a, b) => b.visits - a.visits)

        res.json({ ok: true, pages })
    })

    web.use("/{*any}", (req, res) => res.redirect("/"))
    web.listen(config.web.port, () => console.log(`Kawiso is listening on port ${config.web.port}`))
})()

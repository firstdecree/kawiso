(function () {
    "use strict";

    // Variables
    const script = document.currentScript || document.querySelector("script[data-id][src*=\"analytics.js\"]")
    if (!script) return

    const siteId = script.getAttribute("data-id")
    if (!siteId) return
    const utcOffset = parseInt(script.getAttribute("data-utcoffset") || "0", 10)

    // Functions
    const getScreenSize = ()=>window.screen.width + "x" + window.screen.height
    const getReferrerType = (ref)=>{
        if (!ref) return "direct"
        const searchEngines = ["google", "bing", "duckduckgo", "yahoo", "baidu", "yandex", "ecosia", "ask"]
        const socialNetworks = ["facebook", "twitter", "instagram", "linkedin", "reddit", "tiktok",
            "youtube", "pinterest", "snapchat", "telegram", "whatsapp", "discord"]

        try {
            var host = new URL(ref).hostname.replace(/^www\./, "")

            for (var i = 0; i < searchEngines.length; i++) {
                if (host.indexOf(searchEngines[i]) !== -1) return "search"
            }
            for (var j = 0; j < socialNetworks.length; j++) {
                if (host.indexOf(socialNetworks[j]) !== -1) return "social"
            }
            return "referral"
        } catch{
            return "referral"
        }
    }
    
    const getHourWithOffset = (offset)=>{
        var now = new Date()
        var utcMs = now.getTime() + now.getTimezoneOffset() * 60000
        var localMs = utcMs + offset * 3600000
        return new Date(localMs).getHours()
    }

    const getTimeOfDay = (hour)=>{
        if (hour >= 6 && hour < 12) return "morning"
        if (hour >= 12 && hour < 18) return "afternoon"
        if (hour >= 18 && hour < 24) return "evening"
        return "night"
    }

    const buildFingerprint = ()=>{
        return [
            navigator.language || "",
            getScreenSize(),
            Intl.DateTimeFormat().resolvedOptions().timeZone || "",
            navigator.platform || ""
        ].join("|")
    }

    // Main
    const ref = document.referrer
    const dnt = navigator.doNotTrack || window.doNotTrack || navigator.msDoNotTrack
    const gpc = navigator.globalPrivacyControl

    if (dnt === "1" || dnt === "yes" || gpc) return

    const hour = getHourWithOffset(utcOffset)

    const payload = {
        id: siteId,
        path: window.location.pathname,
        referrer: ref || null,
        refType: getReferrerType(ref),
        language: (navigator.language || "unknown").split("-")[0].toUpperCase(),
        screen: getScreenSize(),
        timeOfDay: getTimeOfDay(hour),
        fingerprint: buildFingerprint(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown",
        ts: Date.now()
    }

    const endpoint = (script.src.replace(/\/analytics\.js.*$/, "")) + "/collect"

    try {
        fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            credentials: "omit",
            keepalive: true
        })
    }catch{}
})()
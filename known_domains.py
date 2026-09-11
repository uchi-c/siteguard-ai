"""
A curated allowlist of extremely well-known, unambiguously legitimate
domains -- used two ways:

1. At runtime (url_safety.py): when Safe Browsing isn't usable (no API
   key, or the call failed) and the target domain is on this list, skip
   the ML fallback entirely and report "no-known-threats" directly. This
   exists because of a real, confirmed failure mode: the ML fallback's
   training data (a Kaggle malicious-URLs dataset) has a "benign" class
   made up mostly of deep-linked content pages, not bare domain
   homepages -- so a bare "www.google.com"-shaped URL statistically
   resembles the dataset's phishing examples (which disproportionately
   impersonate exactly that shape) far more than its benign ones. The
   model confidently (98-99.9%) misclassified google.com and
   wikipedia.org as phishing before this allowlist was added. No static
   model trained once should be fully trusted for the single most common
   real input shape (someone checking a well-known site), so this
   allowlist is a permanent safety net, not a training-data workaround.

2. At training time (ml/train_url_classifier.py): oversampled into the
   benign class so the model also learns the general pattern (a bare,
   short, well-known-brand-shaped domain isn't inherently suspicious),
   not just so these specific domains happen to be hardcoded safe.

Deliberately conservative -- only domains with essentially zero chance of
ever being mistaken for a real risk. Not exhaustive; the point is covering
the sites people overwhelmingly actually check, not building a full
top-1M list.
"""
from __future__ import annotations

KNOWN_SAFE_DOMAINS = frozenset({
    # Search / tech giants
    "google.com", "www.google.com", "bing.com", "www.bing.com",
    "duckduckgo.com", "www.duckduckgo.com", "yahoo.com", "www.yahoo.com",
    "microsoft.com", "www.microsoft.com", "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com", "meta.com", "www.meta.com",

    # Social / communication
    "facebook.com", "www.facebook.com", "instagram.com", "www.instagram.com",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com",
    "linkedin.com", "www.linkedin.com", "reddit.com", "www.reddit.com",
    "pinterest.com", "www.pinterest.com", "tiktok.com", "www.tiktok.com",
    "snapchat.com", "www.snapchat.com", "whatsapp.com", "www.whatsapp.com",
    "telegram.org", "www.telegram.org", "discord.com", "www.discord.com",
    "slack.com", "www.slack.com", "zoom.us", "www.zoom.us",

    # Reference / education / government
    "wikipedia.org", "www.wikipedia.org", "wikimedia.org", "www.wikimedia.org",
    "archive.org", "www.archive.org", "usa.gov", "www.usa.gov",
    "irs.gov", "www.irs.gov", "nih.gov", "www.nih.gov",
    "who.int", "www.who.int", "un.org", "www.un.org",

    # Dev tools / cloud / SaaS
    "github.com", "www.github.com", "gitlab.com", "www.gitlab.com",
    "stackoverflow.com", "www.stackoverflow.com", "npmjs.com", "www.npmjs.com",
    "python.org", "www.python.org", "docker.com", "www.docker.com",
    "cloudflare.com", "www.cloudflare.com", "aws.amazon.com",
    "azure.microsoft.com", "cloud.google.com", "render.com", "www.render.com",
    "vercel.com", "www.vercel.com", "netlify.com", "www.netlify.com",
    "heroku.com", "www.heroku.com", "digitalocean.com", "www.digitalocean.com",
    "atlassian.com", "www.atlassian.com", "notion.so", "www.notion.so",
    "dropbox.com", "www.dropbox.com", "salesforce.com", "www.salesforce.com",
    "anthropic.com", "www.anthropic.com", "claude.ai", "www.claude.ai",
    "openai.com", "www.openai.com",

    # E-commerce / payments / finance
    "paypal.com", "www.paypal.com", "ebay.com", "www.ebay.com",
    "shopify.com", "www.shopify.com", "stripe.com", "www.stripe.com",
    "visa.com", "www.visa.com", "mastercard.com", "www.mastercard.com",
    "chase.com", "www.chase.com", "bankofamerica.com", "www.bankofamerica.com",
    "wellsfargo.com", "www.wellsfargo.com", "americanexpress.com",
    "www.americanexpress.com", "wise.com", "www.wise.com",
    "payoneer.com", "www.payoneer.com",

    # News / media
    "nytimes.com", "www.nytimes.com", "bbc.com", "www.bbc.com",
    "bbc.co.uk", "www.bbc.co.uk", "cnn.com", "www.cnn.com",
    "reuters.com", "www.reuters.com", "theguardian.com", "www.theguardian.com",
    "washingtonpost.com", "www.washingtonpost.com", "forbes.com", "www.forbes.com",
    "bloomberg.com", "www.bloomberg.com", "wsj.com", "www.wsj.com",

    # Streaming / entertainment
    "youtube.com", "www.youtube.com", "netflix.com", "www.netflix.com",
    "spotify.com", "www.spotify.com", "twitch.tv", "www.twitch.tv",
    "hulu.com", "www.hulu.com", "disneyplus.com", "www.disneyplus.com",

    # Productivity / misc widely-used
    "office.com", "www.office.com", "outlook.com", "www.outlook.com",
    "gmail.com", "www.gmail.com", "protonmail.com", "www.protonmail.com",
    "adobe.com", "www.adobe.com", "canva.com", "www.canva.com",
    "wordpress.com", "www.wordpress.com", "wix.com", "www.wix.com",
    "godaddy.com", "www.godaddy.com", "namecheap.com", "www.namecheap.com",
})

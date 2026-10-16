# =============================================================================
#  AegisTik - user configuration
#  Installed as /system script "aegistik-config". The installer creates it
#  once and NEVER overwrites it, so your settings survive engine upgrades.
#
#  The engine loads this script with :parse and expects it to :return an
#  array. Any key you delete falls back to the engine's built-in default.
#  Booleans are written as "yes"/"no".
# =============================================================================

:local cfg [:toarray ""]

# ------------------------------------------------------------------- lists ---
# Address-list that your firewall rules match on.
:set ($cfg->"listName") "AegisTik-Blacklist"
# Address-list of networks that must never be blocked. Add your office, VPN
# peers or monitoring hosts to it from WinBox; it is re-read on every run.
:set ($cfg->"allowListName") "AegisTik-Allowlist"
# Extra never-block networks, comma separated: "203.0.113.10,198.51.100.0/24"
:set ($cfg->"allowlist") ""

# ------------------------------------------------------------------ expiry ---
# Every entry carries this timeout. Each successful run re-creates the
# entries; if updates stop, RouterOS purges them by itself after this time.
# Keep it well above the scheduler interval (minimum 1h).
:set ($cfg->"entryTimeout") "7d"

# --------------------------------------------------------- resource limits ---
# Bytes per HTTP Range request (4096..60000). Use 16000 on 32 MB devices.
:set ($cfg->"chunkSize") 32000
# Hard cap on chunks per feed (chunkSize x maxChunks = largest feed accepted).
:set ($cfg->"maxChunks") 128
# Hard cap on total blacklist entries (roughly 100-150 bytes of RAM each).
:set ($cfg->"maxEntries") 60000
# Abort a feed if free RAM drops below this many bytes.
:set ($cfg->"minFreeMemory") 4194304
# Reject prefixes broader than /N (guards against a broken feed listing /1).
:set ($cfg->"minPrefixLen") 8

# ------------------------------------------------------------------- fetch ---
:set ($cfg->"fetchRetries") 3
:set ($cfg->"retryDelay") "5s"
# Wait this long before starting when the router booted < 5 minutes ago.
:set ($cfg->"bootDelay") "60s"
# "yes-without-crl" (recommended), "yes", or "no" (only if you have no CA store).
:set ($cfg->"checkCertificate") "yes-without-crl"

# ------------------------------------------------------------ anti-lockout ---
# Bogons, RFC1918, CGNAT, loopback, link-local, multicast, reserved space and
# every /ip address network are ALWAYS protected. These add dynamic sources:
:set ($cfg->"protectGateways") "yes"
:set ($cfg->"protectDns") "yes"
:set ($cfg->"protectAdmins") "yes"
:set ($cfg->"protectFeedHosts") "yes"

# ---------------------------------------------------------------- telegram ---
# 1. Create a bot with @BotFather and copy its token.
# 2. Send the bot a message, then open api.telegram.org/bot<TOKEN>/getUpdates
#    in a browser and copy "chat":{"id":...}.
:set ($cfg->"telegramToken") ""
:set ($cfg->"telegramChatId") ""
:set ($cfg->"notifyOnSuccess") "no"
:set ($cfg->"notifyOnFailure") "yes"

# ------------------------------------------------------------------- feeds ---
# format "cidr"    : first token on each line is IP or IP/len (most feeds)
# format "dshield" : DShield block.txt tab-separated layout
# Set "enabled" to "yes" to turn a feed on. Add your own with a new line.
:local feeds [:toarray ""]
:set ($feeds->"spamhaus-drop") {"enabled"="yes"; "format"="cidr"; "url"="https://www.spamhaus.org/drop/drop.txt"}
:set ($feeds->"dshield-top20") {"enabled"="yes"; "format"="dshield"; "url"="https://feeds.dshield.org/block.txt"}
:set ($feeds->"feodo-c2") {"enabled"="yes"; "format"="cidr"; "url"="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"}
:set ($feeds->"et-compromised") {"enabled"="no"; "format"="cidr"; "url"="https://rules.emergingthreats.net/blockrules/compromised-ips.txt"}
:set ($feeds->"cins-army") {"enabled"="no"; "format"="cidr"; "url"="https://cinsscore.com/list/ci-badguys.txt"}
:set ($feeds->"ipsum-level3") {"enabled"="no"; "format"="cidr"; "url"="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"}
:set ($feeds->"blocklist-de") {"enabled"="no"; "format"="cidr"; "url"="https://lists.blocklist.de/lists/all.txt"}
:set ($feeds->"firehol-level1") {"enabled"="no"; "format"="cidr"; "url"="https://iplists.firehol.org/files/firehol_level1.netset"}
:set ($cfg->"feeds") $feeds

:return $cfg

# =============================================================================
#  AegisTik - Dynamic Threat Intelligence Blocker for MikroTik RouterOS v7
#  https://github.com/Mapp25101/AegisTik
#
#  Engine script. Install as /system script "aegistik" (see install.rsc).
#  User settings live in a separate script "aegistik-config", which the
#  installer never overwrites. Everything below has safe built-in defaults.
#
#  Requires : RouterOS 7.13+ (uses the :onerror command)
#  Policy   : ftp,read,write,policy,test
#  License  : MIT
#
#  How a run works
#   1. Load defaults, then merge the user's "aegistik-config" over them.
#   2. Build an anti-lockout "protected" set: bogons/RFC1918/multicast/
#      loopback, every /ip address network, default gateways, DNS servers,
#      logged-in admin sessions, feed and Telegram hosts, and the allowlist.
#   3. Stream each feed with HTTP Range requests in small chunks (no file is
#      written to flash, RAM use stays near one chunk), parse it line by line,
#      drop anything that overlaps the protected set, and add the rest to a
#      staging address-list.
#   4. If a feed fails, its previous entries are carried over unchanged so
#      one dead feed never opens a hole in your protection.
#   5. Swap staging into "AegisTik-Blacklist" with two bulk native commands.
#      The live list stays fully populated while staging is being built.
#   6. Every entry carries a timeout, so RouterOS itself purges entries that
#      stop being refreshed (dead-man switch). They are dynamic entries: they
#      never touch the config database or flash.
#   7. Log a summary and optionally send a Telegram alert.
# =============================================================================

:local atVersion "1.0.0"
:local scriptName "aegistik"
:local cfgScriptName "aegistik-config"

# -----------------------------------------------------------------------------
#  Built-in defaults (override any key in the "aegistik-config" script)
# -----------------------------------------------------------------------------
:local cfg [:toarray ""]
:set ($cfg->"listName") "AegisTik-Blacklist"
:set ($cfg->"allowListName") "AegisTik-Allowlist"
:set ($cfg->"allowlist") ""
:set ($cfg->"entryTimeout") "7d"
:set ($cfg->"chunkSize") 32000
:set ($cfg->"maxChunks") 128
:set ($cfg->"maxEntries") 60000
:set ($cfg->"minPrefixLen") 8
:set ($cfg->"minFreeMemory") 4194304
:set ($cfg->"fetchRetries") 3
:set ($cfg->"retryDelay") "5s"
:set ($cfg->"bootDelay") "60s"
:set ($cfg->"checkCertificate") "yes-without-crl"
:set ($cfg->"protectGateways") "yes"
:set ($cfg->"protectDns") "yes"
:set ($cfg->"protectAdmins") "yes"
:set ($cfg->"protectFeedHosts") "yes"
:set ($cfg->"telegramToken") ""
:set ($cfg->"telegramChatId") ""
:set ($cfg->"notifyOnSuccess") "no"
:set ($cfg->"notifyOnFailure") "yes"
:local defFeeds [:toarray ""]
:set ($defFeeds->"spamhaus-drop") {"enabled"="yes"; "format"="cidr"; "url"="https://www.spamhaus.org/drop/drop.txt"}
:set ($defFeeds->"dshield-top20") {"enabled"="yes"; "format"="dshield"; "url"="https://feeds.dshield.org/block.txt"}
:set ($defFeeds->"feodo-c2") {"enabled"="yes"; "format"="cidr"; "url"="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"}
:set ($cfg->"feeds") $defFeeds

# -----------------------------------------------------------------------------
#  Helper functions. RouterOS functions cannot see the caller's local
#  variables, so every helper takes everything it needs as named arguments.
# -----------------------------------------------------------------------------

# Truthy test that accepts yes/true/1 as string or bool.
:local fnIsOn do={
  :local v [:tostr $1]
  :return ($v = "yes" || $v = "true" || $v = "1" || $v = "on")
}

# Current local date-time as "YYYY-MM-DD HH:MM:SS".
# RouterOS 7.10+ returns ISO dates ("2026-10-16"); older 7.x builds return
# "oct/16/2026". Both are normalised so logs and alerts stay consistent.
:local fnNow do={
  :local d [/system clock get date]
  :local t [:tostr [/system clock get time]]
  :if ([:pick $d 4] != "-") do={
    :local months {"jan"="01";"feb"="02";"mar"="03";"apr"="04";"may"="05";"jun"="06";"jul"="07";"aug"="08";"sep"="09";"oct"="10";"nov"="11";"dec"="12"}
    :set d ([:pick $d 7 11] . "-" . ($months->[:pick $d 0 3]) . "-" . [:pick $d 4 6])
  }
  :return ($d . " " . $t)
}

# Parse one feed line.
#   line   - raw text line
#   fmt    - "cidr"    : first token is IP or IP/len (Spamhaus, abuse.ch, ET, CINS...)
#            "dshield" : "start<TAB>end<TAB>bits<TAB>..." (DShield block.txt)
#   minlen - shortest prefix length accepted (anti-lockout)
# Returns an array {"net"=ip; "bits"=num} with host bits cleared, or one of
# the strings "skip" (blank/comment/IPv6), "bad" (malformed), "wide" (too broad).
:local fnParseLine do={
  :local l [:tostr $line]
  :local n [:len $l]
  :local s 0
  :while ($s < $n && ([:pick $l $s] = " " || [:pick $l $s] = "\t")) do={ :set s ($s + 1) }
  :while ($n > $s && ([:pick $l ($n - 1)] = "\r" || [:pick $l ($n - 1)] = " " || [:pick $l ($n - 1)] = "\t")) do={ :set n ($n - 1) }
  :if ($n <= $s) do={ :return "skip" }
  :set l [:pick $l $s $n]
  :set n [:len $l]
  :local c [:pick $l 0]
  :if ($c = "#" || $c = ";" || $c = "/") do={ :return "skip" }

  :local tok $l
  :local bits 32
  :if ($fmt = "dshield") do={
    :local t1 [:find $l "\t"]
    :if ([:typeof $t1] != "num") do={ :return "bad" }
    :local t2 [:find $l "\t" $t1]
    :if ([:typeof $t2] != "num") do={ :return "bad" }
    :local t3 [:find $l "\t" $t2]
    :if ([:typeof $t3] != "num") do={ :set t3 $n }
    :set tok [:pick $l 0 $t1]
    :set bits [:tonum [:pick $l ($t2 + 1) $t3]]
  } else={
    :local e $n
    :foreach d in={" ";"\t";";";",";"#";"%"} do={
      :local p [:find $l $d]
      :if ([:typeof $p] = "num") do={ :if ($p < $e) do={ :set e $p } }
    }
    :set tok [:pick $l 0 $e]
    :local sl [:find $tok "/"]
    :if ([:typeof $sl] = "num") do={
      :set bits [:tonum [:pick $tok ($sl + 1) [:len $tok]]]
      :set tok [:pick $tok 0 $sl]
    }
  }

  :if ([:typeof [:find $tok ":"]] = "num") do={ :return "skip" }
  :if ([:typeof $bits] != "num") do={ :return "bad" }
  :if ($bits < 0 || $bits > 32) do={ :return "bad" }
  :local ip [:toip $tok]
  :if ([:typeof $ip] != "ip") do={ :return "bad" }
  # Round-trip check rejects odd notations such as "010.1.1.1" or "1.2.3".
  :if ([:tostr $ip] != $tok) do={ :return "bad" }
  :if ($bits < [:tonum $minlen]) do={ :return "wide" }
  :local net $ip
  :if ($bits < 32) do={ :set net ($ip & (255.255.255.255 << (32 - $bits))) }
  :return ({"net"=$net; "bits"=$bits})
}

# True if net/bits overlaps (contains, or is contained by) any protected
# network. Two prefixes overlap when they are equal under the shorter mask.
:local fnHit do={
  :local n [:toip $net]
  :local b [:tonum $bits]
  :local hit false
  :foreach k,pn in=$pnet do={
    :if (!$hit) do={
      :local m [:tonum ($plen->$k)]
      :if ($b < $m) do={ :set m $b }
      :if ($m <= 0) do={
        :set hit true
      } else={
        :local mk (255.255.255.255 << (32 - $m))
        :if (($n & $mk) = ($pn & $mk)) do={ :set hit true }
      }
    }
  }
  :return $hit
}

# Host part of a URL ("https://host:443/path" -> "host").
:local fnUrlHost do={
  :local u [:tostr $1]
  :local p [:find $u "://"]
  :if ([:typeof $p] = "num") do={ :set u [:pick $u ($p + 3) [:len $u]] }
  :foreach d in={"/";":"} do={
    :local q [:find $u $d]
    :if ([:typeof $q] = "num") do={ :set u [:pick $u 0 $q] }
  }
  :return $u
}

# Send a Telegram message (Bot API, JSON POST). Never raises an error.
:local fnTelegram do={
  :if ([:len $token] = 0 || [:len $chat] = 0) do={ :return false }
  :local esc ""
  :for i from=0 to=([:len $text] - 1) do={
    :local ch [:pick $text $i]
    :if ($ch = "\\") do={ :set ch "\\\\" }
    :if ($ch = "\"") do={ :set ch "\\\"" }
    :if ($ch = "\n") do={ :set ch "\\n" }
    :if ($ch = "\r" || $ch = "\t") do={ :set ch " " }
    :set esc ($esc . $ch)
  }
  :local body ("{\"chat_id\":\"" . $chat . "\",\"text\":\"" . $esc . "\",\"disable_notification\":" . $silent . "}")
  :local ok false
  :onerror err in={
    /tool fetch url=("https://api.telegram.org/bot" . $token . "/sendMessage") http-method=post http-header-field="Content-Type: application/json" http-data=$body output=none check-certificate=$cc
    :set ok true
  } do={
    :log warning ("AegisTik: Telegram notification failed: " . $err)
  }
  :return $ok
}

# -----------------------------------------------------------------------------
#  Single-instance lock
# -----------------------------------------------------------------------------
:if ([:len [/system script job find where script=$scriptName]] > 1) do={
  :log warning "AegisTik: another run is still in progress, skipping this one"
  :error "AegisTik: already running"
}

# -----------------------------------------------------------------------------
#  Load user configuration
# -----------------------------------------------------------------------------
:local cfgNote "built-in defaults"
:if ([:len [/system script find where name=$cfgScriptName]] > 0) do={
  :onerror err in={
    :local fnCfg [:parse [/system script get $cfgScriptName source]]
    :local userCfg [$fnCfg]
    :if ([:typeof $userCfg] = "array") do={
      :foreach k,v in=$userCfg do={ :set ($cfg->$k) $v }
      :set cfgNote $cfgScriptName
    } else={
      :log warning ("AegisTik: " . $cfgScriptName . " did not :return an array, using defaults")
    }
  } do={
    :log error ("AegisTik: cannot load " . $cfgScriptName . " (" . $err . "), using defaults")
  }
}

:local listName [:tostr ($cfg->"listName")]
:local stageName ($listName . "-staging")
:local allowListName [:tostr ($cfg->"allowListName")]
:local entryTimeout [:totime ($cfg->"entryTimeout")]
:if ([:typeof $entryTimeout] != "time" || $entryTimeout < 1h) do={ :set entryTimeout 1h }
:local chunkSize [:tonum ($cfg->"chunkSize")]
:if ([:typeof $chunkSize] != "num" || $chunkSize < 4096) do={ :set chunkSize 4096 }
# /tool fetch output=user silently truncates bodies above 64512 bytes.
:if ($chunkSize > 60000) do={ :set chunkSize 60000 }
:local maxChunks [:tonum ($cfg->"maxChunks")]
:if ([:typeof $maxChunks] != "num" || $maxChunks < 1) do={ :set maxChunks 128 }
:local maxEntries [:tonum ($cfg->"maxEntries")]
:if ([:typeof $maxEntries] != "num" || $maxEntries < 1) do={ :set maxEntries 60000 }
:local minPrefix [:tonum ($cfg->"minPrefixLen")]
:if ([:typeof $minPrefix] != "num" || $minPrefix < 1) do={ :set minPrefix 1 }
:local minFree [:tonum ($cfg->"minFreeMemory")]
:if ([:typeof $minFree] != "num") do={ :set minFree 4194304 }
:local retries [:tonum ($cfg->"fetchRetries")]
:if ([:typeof $retries] != "num" || $retries < 1) do={ :set retries 1 }
:local retryDelay [:totime ($cfg->"retryDelay")]
:local cc [:tostr ($cfg->"checkCertificate")]
:local tgToken [:tostr ($cfg->"telegramToken")]
:local tgChat [:tostr ($cfg->"telegramChatId")]
:local feeds ($cfg->"feeds")
:local identity [/system identity get name]
:local tStart [:timestamp]
:global AegisTikStatus
:global AegisTikLastSuccess

:log info ("AegisTik " . $atVersion . ": run started (" . [$fnNow] . ", config: " . $cfgNote . ")")

# Give a freshly booted router time to bring up WAN, DHCP and DNS.
:if ([/system resource get uptime] < 5m) do={ :delay [:totime ($cfg->"bootDelay")] }

# -----------------------------------------------------------------------------
#  Build the anti-lockout protected set
# -----------------------------------------------------------------------------
# Special-purpose IPv4 space (RFC 6890): "this network", RFC1918 private,
# CGNAT, loopback, link-local, IETF, TEST-NETs, benchmarking, multicast and
# reserved/broadcast. Never blocked, whatever a feed says.
:local prot [:toarray "0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,240.0.0.0/4"]

# Every local interface network (LAN, WAN, VPN, PPPoE peer).
:foreach i in=[/ip address find] do={
  :set ($prot->[:len $prot]) [:tostr [/ip address get $i address]]
  :set ($prot->[:len $prot]) [:tostr [/ip address get $i network]]
}

:if ([$fnIsOn ($cfg->"protectGateways")]) do={
  :foreach i in=[/ip route find where dst-address=0.0.0.0/0] do={
    :set ($prot->[:len $prot]) [:tostr [/ip route get $i gateway]]
  }
  :foreach i in=[/ip dhcp-client find] do={
    :onerror err in={ :set ($prot->[:len $prot]) [:tostr [/ip dhcp-client get $i gateway]] } do={}
  }
}

:if ([$fnIsOn ($cfg->"protectDns")]) do={
  :foreach s in=([/ip dns get servers], [/ip dns get dynamic-servers]) do={
    :set ($prot->[:len $prot]) [:tostr $s]
  }
}

:if ([$fnIsOn ($cfg->"protectAdmins")]) do={
  :foreach i in=[/user active find] do={
    :onerror err in={ :set ($prot->[:len $prot]) [:tostr [/user active get $i address]] } do={}
  }
}

:if ([$fnIsOn ($cfg->"protectFeedHosts")]) do={
  :local hosts [:toarray "raw.githubusercontent.com"]
  :if ([:len $tgToken] > 0) do={ :set ($hosts->[:len $hosts]) "api.telegram.org" }
  :foreach fname,f in=$feeds do={ :set ($hosts->[:len $hosts]) [$fnUrlHost ($f->"url")] }
  :foreach h in=$hosts do={
    :onerror err in={ :set ($prot->[:len $prot]) [:tostr [:resolve $h]] } do={}
  }
}

# Static allowlist from config ("1.2.3.4,5.6.7.0/24") plus the allowlist
# address-list that you can manage from WinBox.
:foreach s in=[:toarray ($cfg->"allowlist")] do={ :set ($prot->[:len $prot]) [:tostr $s] }
:foreach i in=[/ip firewall address-list find where list=$allowListName] do={
  :set ($prot->[:len $prot]) [/ip firewall address-list get $i address]
}

:local pNet [:toarray ""]
:local pLen [:toarray ""]
:foreach s in=$prot do={
  :local r [$fnParseLine line=$s fmt="cidr" minlen=0]
  :if ([:typeof $r] = "array") do={
    :set ($pNet->[:len $pNet]) ($r->"net")
    :set ($pLen->[:len $pLen]) ($r->"bits")
  }
}
:log info ("AegisTik: " . [:len $pNet] . " protected networks loaded")

# -----------------------------------------------------------------------------
#  Stream feeds into the staging list
# -----------------------------------------------------------------------------
/ip firewall address-list remove [find where list=$stageName]

:local staged 0
:local feedsOk 0
:local feedsFail 0
:local failedTags [:toarray ""]
:local report ""
:local failReport ""

:foreach fname,f in=$feeds do={
  :if ([$fnIsOn ($f->"enabled")]) do={
    :local url [:tostr ($f->"url")]
    :local fmt [:tostr ($f->"format")]
    :if ([:len $fmt] = 0) do={ :set fmt "cidr" }
    :local tag ("AegisTik:" . $fname)
    :local offset 0
    :local carry ""
    :local chunks 0
    :local done false
    :local failed false
    :local ferr ""
    :local nAdd 0
    :local nDup 0
    :local nProt 0
    :local nBad 0
    :local nWide 0
    :local nCap 0
    :local nValid 0

    :while (!$done) do={
      :set chunks ($chunks + 1)
      :if ($chunks > $maxChunks) do={
        :set failed true
        :set ferr ("feed larger than maxChunks x chunkSize (" . $maxChunks . " x " . $chunkSize . " bytes)")
      }
      :if (!$failed && [/system resource get free-memory] < $minFree) do={
        :set failed true
        :set ferr ("free memory below " . $minFree . " bytes")
      }

      # ---- download one chunk, with retries ----
      :local data ""
      :local got false
      :local eof false
      :local tries 0
      :local hdr ("Range: bytes=" . $offset . "-" . ($offset + $chunkSize - 1) . ",User-Agent: AegisTik/" . $atVersion . " (MikroTik RouterOS)")
      :while (!$failed && !$got && !$eof && $tries < $retries) do={
        :set tries ($tries + 1)
        :onerror err in={
          :local res [/tool fetch url=$url output=user as-value check-certificate=$cc http-header-field=$hdr]
          :if (($res->"status") = "finished") do={
            :set data [:tostr ($res->"data")]
            :set got true
          } else={
            :set ferr ("fetch status " . ($res->"status"))
          }
        } do={
          :set ferr $err
          # 416 = asked for a range past the end: previous chunk was the last.
          :if ($offset > 0 && [:typeof [:find $err "416"]] = "num") do={ :set eof true }
        }
        :if (!$got && !$eof && $tries < $retries) do={ :delay $retryDelay }
      }
      :if (!$got && !$eof) do={ :set failed true }

      :local dlen [:len $data]
      :if ($got) do={
        :if ($offset = 0 && $dlen = 0) do={ :set failed true; :set ferr "empty response" }
        :if ($dlen > $chunkSize && $dlen >= 64512) do={
          :set failed true
          :set ferr "server ignores HTTP Range and the file exceeds 63 KiB"
        }
        # Short chunk = end of file. Longer than requested = the server ignored
        # Range and sent the whole (small) file in one go.
        :if ($dlen != $chunkSize) do={ :set done true }
        :set offset ($offset + $dlen)
      } else={
        :set done true
      }
      :if ($failed) do={ :set done true }

      # ---- parse complete lines; keep the trailing partial line for later ----
      :if (!$failed) do={
        :local buf ($carry . $data)
        :if ($done && [:len $buf] > 0) do={ :set buf ($buf . "\n") }
        :local pos 0
        :local nl [:find $buf "\n"]
        :while ([:typeof $nl] = "num") do={
          :local r [$fnParseLine line=[:pick $buf $pos $nl] fmt=$fmt minlen=$minPrefix]
          :if ([:typeof $r] = "array") do={
            :set nValid ($nValid + 1)
            :if ([$fnHit net=($r->"net") bits=($r->"bits") pnet=$pNet plen=$pLen]) do={
              :set nProt ($nProt + 1)
            } else={
              :if ($staged >= $maxEntries) do={
                :set nCap ($nCap + 1)
              } else={
                :local a [:tostr ($r->"net")]
                :if (($r->"bits") < 32) do={ :set a ($a . "/" . ($r->"bits")) }
                :onerror err in={
                  /ip firewall address-list add list=$stageName address=$a timeout=$entryTimeout comment=$tag
                  :set nAdd ($nAdd + 1)
                  :set staged ($staged + 1)
                } do={
                  :set nDup ($nDup + 1)
                }
              }
            }
          } else={
            :if ($r = "bad") do={ :set nBad ($nBad + 1) }
            :if ($r = "wide") do={ :set nWide ($nWide + 1) }
          }
          :set pos ($nl + 1)
          :set nl [:find $buf "\n" $nl]
        }
        :set carry [:pick $buf $pos [:len $buf]]
      }
    }

    # A feed that produced no usable line (HTML error page, captive portal,
    # format change) is treated as failed instead of wiping its entries.
    :if (!$failed && $nValid = 0) do={ :set failed true; :set ferr "no valid IPv4 entries found" }

    :local stats ("+" . $nAdd . " dup " . $nDup . " protected " . $nProt . " bad " . $nBad . " too-wide " . $nWide)
    :if ($nCap > 0) do={ :set stats ($stats . " capped " . $nCap) }
    :if ($failed) do={
      :set feedsFail ($feedsFail + 1)
      :set ($failedTags->[:len $failedTags]) $tag
      :set failReport ($failReport . "\n- " . $fname . ": " . $ferr)
      :set report ($report . "\n" . $fname . ": FAILED (" . $ferr . ")")
      :log warning ("AegisTik: feed " . $fname . " FAILED: " . $ferr)
    } else={
      :set feedsOk ($feedsOk + 1)
      :set report ($report . "\n" . $fname . ": " . $stats)
      :log info ("AegisTik: feed " . $fname . " OK: " . $stats . " (" . $offset . " bytes, " . $chunks . " chunks)")
    }
  }
}

# -----------------------------------------------------------------------------
#  Carry over previous entries of failed feeds (re-checked against the
#  protected set, in case your WAN address changed since they were added).
# -----------------------------------------------------------------------------
:local carried 0
:foreach tag in=$failedTags do={
  :foreach i in=[/ip firewall address-list find where list=$listName and comment=$tag] do={
    :onerror err in={
      :local a [/ip firewall address-list get $i address]
      :local left [/ip firewall address-list get $i timeout]
      :if ([:typeof $left] != "time" || $left < 1s) do={ :set left $entryTimeout }
      :local r [$fnParseLine line=$a fmt="cidr" minlen=$minPrefix]
      :if ([:typeof $r] = "array") do={
        :if ([$fnHit net=($r->"net") bits=($r->"bits") pnet=$pNet plen=$pLen] = false) do={
          /ip firewall address-list add list=$stageName address=$a timeout=$left comment=$tag
          :set carried ($carried + 1)
          :set staged ($staged + 1)
        }
      }
    } do={}
  }
}
:if ($carried > 0) do={
  :set report ($report . "\ncarried over from failed feeds: " . $carried)
  :log info ("AegisTik: carried over " . $carried . " entries from failed feeds")
}

# -----------------------------------------------------------------------------
#  Swap staging into the live list (or keep the old list if nothing worked)
# -----------------------------------------------------------------------------
:local swapped false
:if ($feedsOk = 0) do={
  /ip firewall address-list remove [find where list=$stageName]
  :log error "AegisTik: all feeds failed, keeping the previous blacklist untouched"
} else={
  :onerror err in={
    /ip firewall address-list remove [find where list=$listName and comment~"^AegisTik:"]
    /ip firewall address-list set [find where list=$stageName] list=$listName
    :set swapped true
  } do={
    :log warning ("AegisTik: bulk swap failed (" . $err . "), moving entries one by one")
  }
  :if (!$swapped) do={
    :foreach i in=[/ip firewall address-list find where list=$stageName] do={
      :onerror err in={
        /ip firewall address-list set $i list=$listName
      } do={
        :onerror err2 in={
          /ip firewall address-list add list=$listName address=[/ip firewall address-list get $i address] timeout=[/ip firewall address-list get $i timeout] comment=[/ip firewall address-list get $i comment]
        } do={}
      }
    }
    /ip firewall address-list remove [find where list=$stageName]
    :set swapped true
  }
}

# -----------------------------------------------------------------------------
#  Summary, status globals and notifications
# -----------------------------------------------------------------------------
:local total [:len [/ip firewall address-list find where list=$listName]]
:local took ([:timestamp] - $tStart)
:local state "OK"
:if ($feedsFail > 0) do={ :set state "DEGRADED" }
:if ($feedsOk = 0) do={ :set state "FAILED" }

:local msg ("AegisTik " . $atVersion . " @ " . $identity . "\n" . [$fnNow] . "\nStatus: " . $state . " (" . $feedsOk . " ok, " . $feedsFail . " failed)\n" . $listName . ": " . $total . " entries" . $report . "\nDuration: " . $took)
:if ($feedsFail > 0 && [:typeof $AegisTikLastSuccess] = "time") do={
  :set msg ($msg . "\nLast successful update: " . ([:timestamp] - $AegisTikLastSuccess) . " ago")
}
:set AegisTikStatus $msg
:if ($state = "OK") do={ :set AegisTikLastSuccess [:timestamp] }

:if ($state = "OK") do={
  :log info ("AegisTik: run finished OK, " . $total . " entries in " . $listName . ", took " . $took)
} else={
  :log warning ("AegisTik: run finished " . $state . ", " . $total . " entries in " . $listName . "." . $failReport)
}

:if ([:len $tgToken] > 0) do={
  :if ($state != "OK" && [$fnIsOn ($cfg->"notifyOnFailure")]) do={
    [$fnTelegram token=$tgToken chat=$tgChat cc=$cc silent="false" text=("\E2\9A\A0 " . $msg)]
  }
  :if ($state = "OK" && [$fnIsOn ($cfg->"notifyOnSuccess")]) do={
    [$fnTelegram token=$tgToken chat=$tgChat cc=$cc silent="true" text=("\E2\9C\85 " . $msg)]
  }
}

# AegisTik-EOF (the installer checks for this marker to detect truncated downloads)

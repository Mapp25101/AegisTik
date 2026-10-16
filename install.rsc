# =============================================================================
#  AegisTik installer / updater - RouterOS v7
#  https://github.com/Mapp25101/AegisTik
#
#  One-line install (paste into a RouterOS terminal):
#    /tool fetch url="https://raw.githubusercontent.com/Mapp25101/AegisTik/main/install.rsc" dst-path=aegistik-install.rsc check-certificate=yes-without-crl; /import file-name=aegistik-install.rsc; /file remove [find where name="aegistik-install.rsc"]
#
#  What it does
#    - checks RouterOS version (7.13+ required)
#    - installs/updates /system script "aegistik" (the engine)
#    - creates /system script "aegistik-config" ONLY if it does not exist yet
#    - creates/updates /system scheduler "aegistik" (at boot + every 12h)
#    - optionally adds the recommended raw firewall rules
#    - starts a first run in the background
#
#  Optional globals, set them before the one-liner:
#    :global AegisTikInterval "6h"   refresh interval (default 12h, minimum 1h)
#    :global AegisTikAddRules "yes"  add raw drop rules for WAN/LAN lists
#    :global AegisTikInsecure "yes"  download without certificate checks
#                                    (only if the router has no CA store)
#
#  Re-running the one-liner upgrades the engine and keeps your config.
#  This file uses the classic ":do {} on-error={}" form so that it can still
#  print a clear version error on RouterOS older than 7.13.
# =============================================================================

:do {
  :local repo "https://raw.githubusercontent.com/Mapp25101/AegisTik/main"
  :global AegisTikInterval
  :global AegisTikAddRules
  :global AegisTikInsecure

  :put "AegisTik installer"

  # ---- RouterOS version check ------------------------------------------
  :local ver [/system resource get version]
  :local dot [:find $ver "."]
  :local major [:tonum [:pick $ver 0 $dot]]
  :local minorStr ""
  :local i ($dot + 1)
  :while ($i < [:len $ver] && [:typeof [:find "0123456789" [:pick $ver $i]]] = "num") do={
    :set minorStr ($minorStr . [:pick $ver $i])
    :set i ($i + 1)
  }
  :local minor [:tonum $minorStr]
  :if ($major < 7 || ($major = 7 && $minor < 13)) do={
    :put ("  ERROR: AegisTik needs RouterOS 7.13 or newer, this router runs " . $ver)
    :error "unsupported RouterOS version"
  }
  :put ("  RouterOS " . $ver . " - OK")

  # ---- options ---------------------------------------------------------
  :local cc "yes-without-crl"
  :if ([:tostr $AegisTikInsecure] = "yes") do={
    :set cc "no"
    :put "  WARNING: certificate verification disabled for downloads"
  }
  :local interval 12h
  :if ([:len [:tostr $AegisTikInterval]] > 0) do={
    :local t [:totime $AegisTikInterval]
    :if ([:typeof $t] = "time" && $t >= 1h) do={ :set interval $t }
  }

  # ---- download helper -------------------------------------------------
  # Returns the file body; raises an error on failure or truncation.
  :local fnGet do={
    :local body ""
    :do {
      :local r [/tool fetch url=$1 output=user as-value check-certificate=$2]
      :if (($r->"status") = "finished") do={ :set body [:tostr ($r->"data")] }
    } on-error={
      :put ("  ERROR: download failed: " . $1)
      :put "  If this is a certificate error, enable the built-in trust store"
      :put "  (RouterOS 7.19+, /certificate settings) or import a CA bundle,"
      :put "  see README. As a last resort set :global AegisTikInsecure \"yes\""
      :error "download failed"
    }
    :if ([:len $body] = 0) do={ :error ("empty download: " . $1) }
    :if ([:len $body] >= 64512) do={ :error ("download truncated (64 KiB fetch limit): " . $1) }
    :return $body
  }

  # ---- engine ----------------------------------------------------------
  :local src [$fnGet ($repo . "/aegistik.rsc") $cc]
  :if ([:typeof [:find $src "AegisTik-EOF"]] != "num") do={
    :put "  ERROR: aegistik.rsc looks incomplete (end marker missing)"
    :error "integrity check failed"
  }
  :if ([:len [/system script find where name="aegistik"]] = 0) do={
    /system script add name="aegistik" policy=ftp,read,write,policy,test dont-require-permissions=no source=$src comment="AegisTik engine - do not edit, overwritten on update"
    :put ("  engine installed (" . [:len $src] . " bytes)")
  } else={
    /system script set [find where name="aegistik"] policy=ftp,read,write,policy,test source=$src
    :put ("  engine updated (" . [:len $src] . " bytes)")
  }

  # ---- configuration (never overwritten) -------------------------------
  :if ([:len [/system script find where name="aegistik-config"]] = 0) do={
    :local csrc [$fnGet ($repo . "/aegistik-config.rsc") $cc]
    /system script add name="aegistik-config" policy=ftp,read,write,policy,test dont-require-permissions=no source=$csrc comment="AegisTik settings - edit me"
    :put "  default config created: /system script aegistik-config"
  } else={
    :put "  existing aegistik-config kept"
  }

  # ---- scheduler -------------------------------------------------------
  :if ([:len [/system scheduler find where name="aegistik"]] = 0) do={
    /system scheduler add name="aegistik" start-time=startup interval=$interval policy=ftp,read,write,policy,test on-event="/system script run aegistik" comment="AegisTik: refresh threat intelligence feeds"
  } else={
    /system scheduler set [find where name="aegistik"] interval=$interval policy=ftp,read,write,policy,test on-event="/system script run aegistik"
  }
  :put ("  scheduler: at boot and every " . $interval)

  # ---- optional firewall rules -----------------------------------------
  # Raw/prerouting drops packets before connection tracking: cheapest place
  # to discard them. Rules go to the top of the raw table, once.
  :if ([:tostr $AegisTikAddRules] = "yes") do={
    :local cmtIn "AegisTik: drop inbound from blacklist"
    :local cmtOut "AegisTik: drop outbound to blacklist"
    :if ([:len [/interface list find where name="WAN"]] = 0) do={
      :put "  skipped inbound rule: interface list WAN does not exist"
    } else={
      :if ([:len [/ip firewall raw find where comment=$cmtIn]] = 0) do={
        /ip firewall raw add chain=prerouting in-interface-list=WAN src-address-list=AegisTik-Blacklist action=drop comment=$cmtIn
        :local first ([/ip firewall raw find]->0)
        :local mine ([/ip firewall raw find where comment=$cmtIn]->0)
        :if ($first != $mine) do={ /ip firewall raw move $mine destination=$first }
        :put ("  added raw rule: " . $cmtIn)
      } else={
        :put ("  raw rule already present: " . $cmtIn)
      }
    }
    :if ([:len [/interface list find where name="LAN"]] = 0) do={
      :put "  skipped outbound rule: interface list LAN does not exist"
    } else={
      :if ([:len [/ip firewall raw find where comment=$cmtOut]] = 0) do={
        /ip firewall raw add chain=prerouting in-interface-list=LAN dst-address-list=AegisTik-Blacklist action=drop comment=$cmtOut
        :local first ([/ip firewall raw find]->0)
        :local mine ([/ip firewall raw find where comment=$cmtOut]->0)
        :if ($first != $mine) do={ /ip firewall raw move $mine destination=$first }
        :put ("  added raw rule: " . $cmtOut)
      } else={
        :put ("  raw rule already present: " . $cmtOut)
      }
    }
  } else={
    :put "  firewall rules NOT added - see README for the recommended rules"
  }

  # ---- first run -------------------------------------------------------
  :execute script="/system script run aegistik"
  :put "  first run started in background - watch it with: /log print follow where message~\"AegisTik\""
  :put "AegisTik installation complete."
} on-error={
  :put "AegisTik installation aborted - nothing was started. See messages above."
}

# Clean up installer option globals.
/system script environment remove [find where name~"^AegisTik(Interval|AddRules|Insecure)\$"]

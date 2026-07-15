#!/bin/bash

TARGET=$1
OUTDIR="recon_$TARGET"
NMAP_OUT="$OUTDIR/nmap_full.txt"
REPORT_MD="$OUTDIR/report_${TARGET}.md"
REPORT_PDF="$OUTDIR/report_${TARGET}.pdf"
NUCLEI_OUT="$OUTDIR/nuclei_http.txt"
EXPLOIT_OUT="$OUTDIR/searchsploit_results.txt"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

# Tools check list
tools=(nmap httpx whatweb gobuster feroxbuster ffuf nikto nuclei hydra ncrack ssh-audit enum4linux smbclient nxc smbmap snmpwalk onesixtyone ldapsearch smtp-user-enum rpcclient dig dnsenum showmount searchsploit pandoc wpscan gowitness sqlmap)
missing_tools=()

for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        if [ "$tool" = "nxc" ] && command -v netexec &> /dev/null; then
            continue
        fi
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "[!] The following tools are missing: ${missing_tools[*]}"
    echo "[*] Attempting to install missing tools via install_recon_tools.sh..."
    if [ -f ./install_recon_tools.sh ]; then
        bash ./install_recon_tools.sh
    else
        echo "[!] install_recon_tools.sh not found. Please install the missing tools manually."
        exit 1
    fi
fi

mkdir -p "$OUTDIR"

run_with_timeout_skip() {
    local cmd="$1"
    local timeout_duration="${2:-300}"
    echo "[*] Running (with timeout ${timeout_duration}s): $cmd"

    trap 'echo -e "\n[!] Skipping current command due to Ctrl+C"; return 130' SIGINT

    timeout "${timeout_duration}s" bash -c "exec $cmd"
    local status=$?

    if [ $status -eq 124 ]; then
        echo "[!] Command timed out after ${timeout_duration}s and was killed."
    elif [ $status -eq 130 ]; then
        echo "[!] Command skipped by user (Ctrl+C)."
    fi

    trap - SIGINT
    return $status
}

GREEN="\033[1;32m"
RESET="\033[0m"

# hacker banner created with font 'Small' https://patorjk.com/software/taag/#p=display&f=Small
print_hacker_banner() {
    local word="$1"
    echo -e "${GREEN}"
    case "$word" in
        "NMAP")
            cat << "EOF"
  _  _ __  __   _   ___ 
 | \| |  \/  | /_\ | _ \
 | .` | |\/| |/ _ \|  _/
 |_|\_|_|  |_/_/ \_\_|  
EOF
            ;;
        "WHATWEB")
            cat << "EOF"
 __      ___  _   _ _______      _____ ___ 
 \ \    / / || | /_\_   _\ \    / / __| _ )
  \ \/\/ /| __ |/ _ \| |  \ \/\/ /| _|| _ \
   \_/\_/ |_||_/_/ \_\_|   \_/\_/ |___|___/                            
EOF
            ;;
        "HTTPX")
            cat << "EOF"
  _  _ _____ _____ _____  __
 | || |_   _|_   _| _ \ \/ /
 | __ | | |   | | |  _/>  < 
 |_||_| |_|   |_| |_| /_/\_\     
EOF
            ;;
        "GOBUSTER")
            cat << "EOF"
   ___  ___  ___ _   _ ___ _____ ___ ___ 
  / __|/ _ \| _ ) | | / __|_   _| __| _ \
 | (_ | (_) | _ \ |_| \__ \ | | | _||   /
  \___|\___/|___/\___/|___/ |_| |___|_|_\                                                  
EOF
            ;;
        "NUCLEI")
            cat << "EOF"
  _  _ _   _  ___ _    ___ ___ 
 | \| | | | |/ __| |  | __|_ _|
 | .` | |_| | (__| |__| _| | | 
 |_|\_|\___/ \___|____|___|___|                     
EOF
            ;;
        "NIKTO")
            cat << "EOF"
  _  _ ___ _  _______ ___  
 | \| |_ _| |/ /_   _/ _ \ 
 | .` || || ' <  | || (_) |
 |_|\_|___|_|\_\ |_| \___/                 
EOF
            ;;
        "FEROXBUSTER")
            cat << "EOF"
  ___ ___ ___  _____  _____ _   _ ___ _____ ___ ___ 
 | __| __| _ \/ _ \ \/ / _ ) | | / __|_   _| __| _ \
 | _|| _||   / (_) >  <| _ \ |_| \__ \ | | | _||   /
 |_| |___|_|_\\___/_/\_\___/\___/|___/ |_| |___|_|_\                                
EOF
            ;;
        "NETEXEC")
            cat << "EOF"
  _  _ ___ _____ _____  _____ ___ 
 | \| | __|_   _| __\ \/ / __/ __|
 | .` | _|  | | | _| >  <| _| (__ 
 |_|\_|___| |_| |___/_/\_\___\___|                          
EOF
            ;;
        "SQLMAP")
            cat << "EOF"
  ___  ___  _    __  __   _   ___ 
 / __|/ _ \| |  |  \/  | /_\ | _ \
 \__ \ (_) | |__| |\/| |/ _ \|  _/
 |___/\__\_\____|_|  |_/_/ \_\_|                               
EOF
            ;;
        "HYDRA")
            cat << "EOF"
  _  ___   _____  ___    _   
 | || \ \ / /   \| _ \  /_\  
 | __ |\ V /| |) |   / / _ \ 
 |_||_| |_| |___/|_|_\/_/ \_\                             
EOF
            ;;
        "NCRACK")
            cat << "EOF"
  _  _  ___ ___    _   ___ _  __
 | \| |/ __| _ \  /_\ / __| |/ /
 | .` | (__|   / / _ \ (__| ' < 
 |_|\_|\___|_|_\/_/ \_\___|_|\_\                             
EOF
            ;;
        "SSH-AUDIT")
            cat << "EOF"
  ___ ___ _  _      _  _   _ ___ ___ _____ 
 / __/ __| || |___ /_\| | | |   \_ _|_   _|
 \__ \__ \ __ |___/ _ \ |_| | |) | |  | |  
 |___/___/_||_|  /_/ \_\___/|___/___| |_|                             
EOF
            ;;
        "ENUM4LINUX")
            cat << "EOF"
  ___ _  _ _   _ __  __ _ _  _    ___ _  _ _   ___  __
 | __| \| | | | |  \/  | | || |  |_ _| \| | | | \ \/ /
 | _|| .` | |_| | |\/| |_  _| |__ | || .` | |_| |>  < 
 |___|_|\_|\___/|_|  |_| |_||____|___|_|\_|\___//_/\_\                             
EOF
            ;;
        "SMBCLIENT")
            cat << "EOF"
  ___ __  __ ___  ___ _    ___ ___ _  _ _____ 
 / __|  \/  | _ )/ __| |  |_ _| __| \| |_   _|
 \__ \ |\/| | _ \ (__| |__ | || _|| .` | | |  
 |___/_|  |_|___/\___|____|___|___|_|\_| |_|                                
EOF
            ;;
        "SMBMAP")
            cat << "EOF"
  ___ __  __ ___ __  __   _   ___ 
 / __|  \/  | _ )  \/  | /_\ | _ \
 \__ \ |\/| | _ \ |\/| |/ _ \|  _/
 |___/_|  |_|___/_|  |_/_/ \_\_|                               
EOF
            ;;
        "SNMPWALK")
            cat << "EOF"
  ___ _  _ __  __ _____      ___   _    _  __
 / __| \| |  \/  | _ \ \    / /_\ | |  | |/ /
 \__ \ .` | |\/| |  _/\ \/\/ / _ \| |__| ' < 
 |___/_|\_|_|  |_|_|   \_/\_/_/ \_\____|_|\_\                             
EOF
            ;;
        "ONESIXTYONE")
            cat << "EOF"
   ___  _  _ ___ ___ _____  _________   _____  _  _ ___ 
  / _ \| \| | __/ __|_ _\ \/ /_   _\ \ / / _ \| \| | __|
 | (_) | .` | _|\__ \| | >  <  | |  \ V / (_) | .` | _| 
  \___/|_|\_|___|___/___/_/\_\ |_|   |_| \___/|_|\_|___|                           
EOF
            ;;
        "LDAPSEARCH")
            cat << "EOF"
  _    ___   _   ___  ___ ___   _   ___  ___ _  _ 
 | |  |   \ /_\ | _ \/ __| __| /_\ | _ \/ __| || |
 | |__| |) / _ \|  _/\__ \ _| / _ \|   / (__| __ |
 |____|___/_/ \_\_|  |___/___/_/ \_\_|_\\___|_||_|                             
EOF
            ;;
        "SMTP-USER-ENUM")
            cat << "EOF"
  ___ __  __ _____ ___     _   _ ___ ___ ___     ___ _  _ _   _ __  __ 
 / __|  \/  |_   _| _ \___| | | / __| __| _ \___| __| \| | | | |  \/  |
 \__ \ |\/| | | | |  _/___| |_| \__ \ _||   /___| _|| .` | |_| | |\/| |
 |___/_|  |_| |_| |_|      \___/|___/___|_|_\   |___|_|\_|\___/|_|  |_|                            
EOF
            ;;
        "RPCCLIENT")
            cat << "EOF"
  ___ ___  ___ ___ _    ___ ___ _  _ _____ 
 | _ \ _ \/ __/ __| |  |_ _| __| \| |_   _|
 |   /  _/ (_| (__| |__ | || _|| .` | | |  
 |_|_\_|  \___\___|____|___|___|_|\_| |_|                             
EOF
            ;;
        "DIG")
            cat << "EOF"
  ___ ___ ___ 
 |   \_ _/ __|
 | |) | | (_ |
 |___/___\___|                             
EOF
            ;;
        "DNSENUM")
            cat << "EOF"
  ___  _  _ ___ ___ _  _ _   _ __  __ 
 |   \| \| / __| __| \| | | | |  \/  |
 | |) | .` \__ \ _|| .` | |_| | |\/| |
 |___/|_|\_|___/___|_|\_|\___/|_|  |_|                            
EOF
            ;;
        "SHOWMOUNT")
            cat << "EOF"
  ___ _  _  _____      ____  __  ___  _   _ _  _ _____ 
 / __| || |/ _ \ \    / /  \/  |/ _ \| | | | \| |_   _|
 \__ \ __ | (_) \ \/\/ /| |\/| | (_) | |_| | .` | | |  
 |___/_||_|\___/ \_/\_/ |_|  |_|\___/ \___/|_|\_| |_|                             
EOF
            ;;
        "SEARCHSPLOIT")
            cat << "EOF"
  ___ ___   _   ___  ___ _  _ ___ ___ _    ___ ___ _____ 
 / __| __| /_\ | _ \/ __| || / __| _ \ |  / _ \_ _|_   _|
 \__ \ _| / _ \|   / (__| __ \__ \  _/ |_| (_) | |  | |  
 |___/___/_/ \_\_|_\\___|_||_|___/_| |____\___/___| |_|                             
EOF
            ;;
        "PANDOC")
            cat << "EOF"
  ___  _   _  _ ___   ___   ___ 
 | _ \/_\ | \| |   \ / _ \ / __|
 |  _/ _ \| .` | |) | (_) | (__ 
 |_|/_/ \_\_|\_|___/ \___/ \___|                           
EOF
            ;;
        "WPSCAN")
            cat << "EOF"
 __      _____  ___  ___   _   _  _ 
 \ \    / / _ \/ __|/ __| /_\ | \| |
  \ \/\/ /|  _/\__ \ (__ / _ \| .` |
   \_/\_/ |_|  |___/\___/_/ \_\_|\_|                          
EOF
            ;;
        "GOWITNESS")
            cat << "EOF"
   ___  _____      _____ _____ _  _ ___ ___ ___ 
  / __|/ _ \ \    / /_ _|_   _| \| | __/ __/ __|
 | (_ | (_) \ \/\/ / | |  | | | .` | _|\__ \__ \
  \___|\___/ \_/\_/ |___| |_| |_|\_|___|___/___/                            
EOF
            ;;
        "FUFF")
            cat << "EOF"
  ___ _   _ ___ ___ 
 | __| | | | __| __|
 | _|| |_| | _|| _| 
 |_|  \___/|_| |_|  
EOF
            ;;
    esac
    echo -e "${RESET}"
}

# TCP Full Scan
print_hacker_banner "NMAP"
run_with_timeout_skip "nmap -p- -T4 -oN \"$OUTDIR/nmap_tcp.txt\" \"$TARGET\"" 600

# Extract TCP Ports
TCP_PORTS=$(grep '/tcp' "$OUTDIR/nmap_tcp.txt" | cut -d '/' -f1 | paste -sd ',' -)

if [ -z "$TCP_PORTS" ]; then
    echo "[!] No open TCP ports found. Skipping service detection."
else
    run_with_timeout_skip "nmap -sC -sV -p $TCP_PORTS -oN \"$OUTDIR/nmap_tcp_services.txt\" \"$TARGET\"" 600
fi

# UDP Top 100
run_with_timeout_skip "nmap -sU --top-ports 100 -T4 -oN \"$OUTDIR/nmap_udp.txt\" \"$TARGET\"" 300

touch "$OUTDIR/nmap_tcp_services.txt" "$OUTDIR/nmap_udp.txt" "$OUTDIR/nmap_tcp.txt"
cat "$OUTDIR/nmap_tcp_services.txt" "$OUTDIR/nmap_udp.txt" "$OUTDIR/nmap_tcp.txt" > "$OUTDIR/nmap_services.txt"

# Enumeration tools
run_enum_tools() {
    echo "[*] Checking services for enumeration..."

    # HTTP/HTTPS
    if grep -iE '^[0-9]+/(tcp|udp).*http' "$OUTDIR/nmap_services.txt" > /dev/null; then
        echo "[+] HTTP detected"
        echo "http://$TARGET" > urls.txt
        echo "https://$TARGET" >> urls.txt
    
        print_hacker_banner "WHATWEB"
        run_with_timeout_skip "whatweb -i urls.txt --log-verbose=\"$OUTDIR/whatweb.txt\"" 180
        
        print_hacker_banner "HTTPX"
        run_with_timeout_skip "httpx http://$TARGET --follow-redirects --download \"$OUTDIR/httpx.txt\"" 180
        
        print_hacker_banner "GOBUSTER"
        run_with_timeout_skip "gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o \"$OUTDIR/gobuster_http.txt\"" 300
        run_with_timeout_skip "gobuster dir -u https://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o \"$OUTDIR/gobuster_https.txt\"" 300
        
        if command -v nuclei &> /dev/null; then
            print_hacker_banner "NUCLEI"
            run_with_timeout_skip "nuclei -list urls.txt -silent -o \"$NUCLEI_OUT\"" 300
        fi
        
        print_hacker_banner "NIKTO"
        # If HTTP is open on port 80, scan without SSL checks to prevent hanging
        if grep -qi "80/tcp" "$OUTDIR/nmap_tcp.txt" 2>/dev/null; then
            echo "[*] Launching Nikto on Port 80 (Plain HTTP - skipping SSL checks)..."
            run_with_timeout_skip "nikto -h http://$TARGET -nossl -Format txt -output \"$OUTDIR/nikto_http.txt\" -Display V" 180
        fi

        # If HTTPS is detected, force SSL mode
        if grep -qiE "443/tcp|https" "$OUTDIR/nmap_services.txt" 2>/dev/null; then
            echo "[*] Launching Nikto on SSL/TLS endpoint..."
            run_with_timeout_skip "nikto -h https://$TARGET -ssl -Format txt -output \"$OUTDIR/nikto_https.txt\" -Display V" 180
        fi
        
        print_hacker_banner "FEROXBUSTER"
        run_with_timeout_skip "feroxbuster -u http://$TARGET --scan-dir-listings -o \"$OUTDIR/feroxbuster.txt\"" 300       
        run_with_timeout_skip "feroxbuster -u https://$TARGET --scan-dir-listings -o \"$OUTDIR/feroxbuster_https.txt\"" 300

        # WPScan
        if grep -qi "wordpress" "$OUTDIR/nmap_services.txt" || curl -s "http://$TARGET" | grep -qi "wp-content"; then
            print_hacker_banner "WPSCAN"
            echo "[+] WordPress detected, launching WPScan..."
            run_with_timeout_skip "wpscan --url http://$TARGET --enumerate vp,vt,cb,dbe,u --no-update --disable-tls-checks -o \"$OUTDIR/wpscan.txt\"" 300
        fi

        # GoWitness
        if command -v gowitness &> /dev/null; then
            print_hacker_banner "GOWITNESS"
            echo "[+] Capturing web interface screenshots..."
            run_with_timeout_skip "gowitness file -f urls.txt --destination \"$OUTDIR/screenshots\" --write-db=false" 180
        fi

        # SQLMap (Crawls and form testing safely)
        if command -v sqlmap &> /dev/null; then
            print_hacker_banner "SQLMAP"
            echo "[+] Launching SQLMap crawl scan on targets..."
            run_with_timeout_skip "sqlmap -u http://$TARGET --crawl=2 --batch --random-agent --forms --level=1 --risk=1 -o \"$OUTDIR/sqlmap_crawl.txt\"" 300
        fi

        # VHost Fuzzing Block (Dynamic Content-Length logic)
        echo "[*] Dynamically detecting baseline response for bogus Virtual Hosts..."
        # Query a nonexistent vhost to find the standard error length
        BASELINE_SIZE=$(curl -s -o /dev/null -D - -H "Host: nonexistentdomain123.inlanefreight.local" http://$TARGET | grep -i "Content-Length" | awk '{print $2}' | tr -d '\r')
        
        # Default fallback size if query fails
        if [ -z "$BASELINE_SIZE" ]; then
            BASELINE_SIZE="15157"
        fi
        echo "[+] Nonexistent VHost responds with size: $BASELINE_SIZE"

        # Check for directory dictionary inside default SecLists paths
        VHOST_WORDLIST="/usr/share/seclists/Discovery/DNS/namelist.txt"
        if [ ! -f "$VHOST_WORDLIST" ] && [ -f "/opt/useful/seclists/Discovery/DNS/namelist.txt" ]; then
            VHOST_WORDLIST="/opt/useful/seclists/Discovery/DNS/namelist.txt"
        fi

        if [ -f "$VHOST_WORDLIST" ]; then
            print_hacker_banner "FUFF"
            echo "[+] Launching VHost fuzzing with FFUF (filtering size: $BASELINE_SIZE)..."
            run_with_timeout_skip "ffuf -w $VHOST_WORDLIST:FUZZ -u http://$TARGET/ -H 'Host: FUZZ.inlanefreight.local' -fs $BASELINE_SIZE -t 50 -o \"$OUTDIR/ffuf_vhosts.json\"" 300
        fi

        echo "HTTP scan done!"
    fi

    # FTP (Safely falling back if rockyou is missing)
    if grep -qi "ftp" "$OUTDIR/nmap_services.txt"; then
        print_hacker_banner "HYDRA"
        echo "[+] FTP detected"
        echo -e "open $TARGET\nanonymous\nanonymous\nls\nbye" | ftp -n > "$OUTDIR/ftp_check.txt" 2>/dev/null
        
        if [ -f /usr/share/wordlists/rockyou.txt ]; then
            run_with_timeout_skip "hydra -l anonymous -P /usr/share/wordlists/rockyou.txt -t 4 ftp://$TARGET -o \"$OUTDIR/ftp_hydra.txt\"" 300
        else
            echo "[!] rockyou.txt missing — attempting lightweight FTP guest bypass check instead"
            run_with_timeout_skip "hydra -l anonymous -p anonymous -t 4 ftp://$TARGET -o \"$OUTDIR/ftp_hydra.txt\"" 120
        fi
    fi

    # SMB
    if grep -qi "smb" "$OUTDIR/nmap_services.txt" || grep -qi "netbios" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMB detected"
        
        print_hacker_banner "ENUM4LINUX"
        run_with_timeout_skip "enum4linux -a \"$TARGET\" > \"$OUTDIR/enum4linux.txt\"" 300
        
        print_hacker_banner "SMBCLIENT"
        run_with_timeout_skip "smbclient -L \\\\$TARGET -N > \"$OUTDIR/smbclient.txt\"" 120
        
        # NetExec / nxc
        if command -v nxc &> /dev/null; then
            print_hacker_banner "NETEXEC"
            run_with_timeout_skip "nxc smb $TARGET --shares > \"$OUTDIR/nxc_shares.txt\"" 180
        elif command -v netexec &> /dev/null; then
            print_hacker_banner "NETEXEC"
            run_with_timeout_skip "netexec smb $TARGET --shares > \"$OUTDIR/nxc_shares.txt\"" 180
        fi
        
        print_hacker_banner "SMBMAP"
        run_with_timeout_skip "smbmap -H $TARGET > \"$OUTDIR/smbmap.txt\"" 180
    fi

    # SSH
    if grep -qi "ssh" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SSH detected"
        # Extract version
        run_with_timeout_skip "ssh -v -o BatchMode=yes -o ConnectTimeout=3 user@$TARGET 2>&1 | grep 'SSH-' > \"$OUTDIR/ssh_version.txt\"" 120
        
        if command -v ssh-audit &> /dev/null; then
            print_hacker_banner "SSH-AUDIT"
            run_with_timeout_skip "ssh-audit $TARGET > \"$OUTDIR/ssh_audit.txt\"" 180
        fi
    fi

    # RDP
    if grep -qi "ms-wbt-server" "$OUTDIR/nmap_services.txt"; then
        echo "[+] RDP detected"
        run_with_timeout_skip "rdpscan $TARGET > \"$OUTDIR/rdpscan.txt\"" 180
        if [ -f /usr/share/wordlists/usernames.txt ] && [ -f /usr/share/wordlists/rockyou.txt ]; then
            print_hacker_banner "NCRACK"
            run_with_timeout_skip "ncrack -p 3389 -U /usr/share/wordlists/usernames.txt -P /usr/share/wordlists/rockyou.txt $TARGET -oN \"$OUTDIR/rdp_ncrack.txt\"" 300
        fi
    fi

    # SNMP
    if grep -qi "snmp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SNMP detected"
        
        print_hacker_banner "SNMPWALK"
        run_with_timeout_skip "snmpwalk -v1 -c public $TARGET > \"$OUTDIR/snmpwalk.txt\"" 180
        
        print_hacker_banner "ONESIXTYONE"
        run_with_timeout_skip "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $TARGET > \"$OUTDIR/onesixtyone.txt\"" 180
    fi

    # LDAP
    if grep -qi "ldap" "$OUTDIR/nmap_services.txt"; then
        print_hacker_banner "LDAPSEARCH"
        echo "[+] LDAP detected"
        run_with_timeout_skip "ldapsearch -x -H ldap://$TARGET -s base > \"$OUTDIR/ldapsearch.txt\"" 180
    fi

    # SMTP (Checks file availability before executing)
    if grep -qi "smtp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMTP detected"
        if [ -f /usr/share/wordlists/usernames.txt ]; then
            print_hacker_banner "SMTP-USER-ENUM"
            run_with_timeout_skip "smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t $TARGET > \"$OUTDIR/smtp_enum.txt\"" 300
        else
            echo "[!] /usr/share/wordlists/usernames.txt missing — skipping SMTP user enum."
        fi
    fi

    # RPC
    if grep -qi "rpcbind" "$OUTDIR/nmap_services.txt"; then
        print_hacker_banner "RPCCLIENT"
        echo "[+] RPC detected"
        run_with_timeout_skip "rpcclient -U \"\" $TARGET -c enumdomusers > \"$OUTDIR/rpc_enum.txt\"" 180
    fi

    # DNS (Handles Zone Transfers Dynamically using the target domain name)
    if grep -qi "domain" "$OUTDIR/nmap_services.txt"; then
        echo "[+] DNS detected. Attempting Dynamic Domain Identification..."
        
        # Auto-discover or fallback domain setting
        DOMAIN="inlanefreight.local"
        if grep -qi "inlanefreight" "$OUTDIR/nmap_services.txt"; then
            DOMAIN="inlanefreight.local"
        fi
        
        print_hacker_banner "DIG"
        # Run dynamic DNS Zone Transfer
        run_with_timeout_skip "dig axfr @$TARGET $DOMAIN > \"$OUTDIR/dns_zone.txt\"" 120
        
        # Save identified subdomains list for simple copy-pasting hosts later
        if [ -s "$OUTDIR/dns_zone.txt" ]; then
            grep -E 'IN[[:space:]]+A' "$OUTDIR/dns_zone.txt" | awk '{print $1}' | sed 's/\.$//' | sort -u > "$OUTDIR/discovered_hosts.txt"
        fi
        
        print_hacker_banner "DNSENUM"
        run_with_timeout_skip "dnsenum --dnsserver $TARGET $DOMAIN > \"$OUTDIR/dnsenum.txt\"" 300
    fi

    # NFS
    if grep -qi "nfs" "$OUTDIR/nmap_services.txt"; then
        print_hacker_banner "SHOWMOUNT"
        echo "[+] NFS detected"
        run_with_timeout_skip "showmount -e $TARGET > \"$OUTDIR/nfs_exports.txt\"" 120
    fi
}

# SearchSploit
run_searchsploit() {
    print_hacker_banner "SEARCHSPLOIT"
    echo "[*] Running SearchSploit on service versions..."
    > "$EXPLOIT_OUT"

    while IFS= read -r line; do
        if [[ "$line" =~ [0-9]+/tcp ]]; then
            service_line=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | xargs)
            if [ -n "$service_line" ]; then
                echo "[+] Searching: $service_line"
                echo "### $service_line" >> "$EXPLOIT_OUT"
                run_with_timeout_skip "searchsploit \"$service_line\" >> \"$EXPLOIT_OUT\"" 60
                echo >> "$EXPLOIT_OUT"
            fi
        fi
    done < "$OUTDIR/nmap_services.txt"
}

# Execute sequence
run_enum_tools
run_searchsploit

# Markdown aggregation
{
echo "# Recon Report for $TARGET"
echo "_Generated: $TIMESTAMP_"
echo

for file in "$OUTDIR"/*.txt; do
    [ -f "$file" ] || continue
    echo "## $(basename "$file")"
    echo '```'
    cat "$file"
    echo '```'
    echo
done
} > "$REPORT_MD"

if command -v pandoc &> /dev/null; then
    print_hacker_banner "PANDOC"
    pandoc "$REPORT_MD" -o "$REPORT_PDF"
    echo "[+] PDF report saved to: $REPORT_PDF"
else
    echo "[!] pandoc not found — skipping PDF generation"
fi

# Print out /etc/hosts formatted lines for quick terminal mapping
if [ -s "$OUTDIR/discovered_hosts.txt" ]; then
    echo -e "\n${GREEN}[!] DISCOVERED HOSTS (Copy and paste into your /etc/hosts file):${RESET}"
    echo -e "--------------------------------------------------------"
    echo -n "sudo tee -a /etc/hosts > /dev/null <<EOT"
    echo -e "\n$TARGET inlanefreight.local"
    while read -r host; do
        if [ "$host" != "inlanefreight.local" ]; then
            echo "$TARGET $host"
        fi
    done < "$OUTDIR/discovered_hosts.txt"
    echo "EOT"
    echo -e "--------------------------------------------------------"
fi

echo "[*] Done. All results saved in $OUTDIR/"

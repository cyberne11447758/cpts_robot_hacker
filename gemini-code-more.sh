#!/bin/bash

TARGET=$1
DOMAIN_ARG=$2 # Optional second parameter to lock down the scoping domain
OUTDIR="recon_$TARGET"
NMAP_OUT="$OUTDIR/nmap_full.txt"
REPORT_MD="$OUTDIR/report_${TARGET}.md"
REPORT_PDF="$OUTDIR/report_${TARGET}.pdf"
NUCLEI_OUT="$OUTDIR/nuclei_http.txt"
EXPLOIT_OUT="$OUTDIR/searchsploit_results.txt"
TARGETS_LIST="$OUTDIR/discovered_targets.txt"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip> [optional-domain]"
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
> "$OUTDIR/discovered_hosts.txt"

run_with_timeout_skip() {
    local cmd="$1"
    local timeout_duration="${2:-300}"
    echo "[*] Running: $cmd"

    eval "$cmd" &
    local pid=$!

    trap 'echo -e "\n[!] Forcefully breaking stuck execution ($pid)..."; kill -9 $pid 2>/dev/null; killall ffuf nikto sqlmap feroxbuster hydra 2>/dev/null; wait $pid 2>/dev/null; trap - INT; return 130' INT

    local count=0
    while kill -0 $pid 2>/dev/null; do
        sleep 1
        let count+=1
        if [ $count -ge $timeout_duration ]; then
            echo "[!] Command reached max runtime ceiling (${timeout_duration}s) and was terminated."
            kill -9 $pid 2>/dev/null
            wait $pid 2>/dev/null
            trap - INT
            return 124
        fi
    done

    wait $pid
    local status=$?
    trap - INT
    return $status
}

GREEN="\033[1;32m"
RESET="\033[0m"

print_hacker_banner() {
    local word="$1"
    echo -e "${GREEN}"
    case "$word" in
        "NMAP") cat << "EOF"
  _  _ __  __   _   ___ 
 | \| |  \/  | /_\ | _ \
 | .` | |\/| |/ _ \|  _/
 |_|\_|_|  |_/_/ \_\_|  
EOF
        ;;
        "WHATWEB") cat << "EOF"
 __      ___  _   _ _______      _____ ___ 
 \ \    / / || | /_\_   _\ \    / / __| _ )
  \ \/\/ /| __ |/ _ \| |  \ \/\/ /| _|| _ \
   \_/\_/ |_||_/_/ \_\_|   \_/\_/ |___|___/                            
EOF
        ;;
        "HTTPX") cat << "EOF"
  _  _ _____ _____ _____  __
 | || |_   _|_   _| _ \ \/ /
 | __ | | |   | | |  _/>  < 
 |_||_| |_|   |_| |_| /_/\_\     
EOF
        ;;
        "GOBUSTER") cat << "EOF"
   ___  ___  ___ _   _ ___ _____ ___ ___ 
  / __|/ _ \| _ ) | | / __|_   _| __| _ \
 | (_ | (_) | _ \ |_| \__ \ | | | _||   /
  \___|\___/|___/\___/|___/ |_| |___|_|_\                                                  
EOF
        ;;
        "NUCLEI") cat << "EOF"
  _  _ _   _  ___ _    ___ ___ 
 | \| | | | |/ __| |  | __|_ _|
 | .` | |_| | (__| |__| _| | | 
 |_|\_|\___/ \___|____|___|___|                     
EOF
        ;;
        "NIKTO") cat << "EOF"
  _  _ ___ _  _______ ___  
 | \| |_ _| |/ /_   _/ _ \ 
 | .` || || ' <  | || (_) |
 |_|\_|___|_|\_\ |_| \___/                 
EOF
        ;;
        "FEROXBUSTER") cat << "EOF"
  ___ ___ ___  _____  _____ _   _ ___ _____ ___ ___ 
 | __| __| _ \/ _ \ \/ / _ ) | | / __|_   _| __| _ \
 | _|| _||   / (_) >  <| _ \ |_| \__ \ | | | _||   /
 |_| |___|_|_\\___/_/\_\___/\___/|___/ |_| |___|_|_\                                
EOF
        ;;
        "NETEXEC") cat << "EOF"
  _  _ ___ _____ _____  _____ ___ 
 | \| | __|_   _| __\ \/ / __/ __|
 | .` | _|  | | | _| >  <| _| (__ 
 |_|\_|___| |_| |___/_/\_\___\___|                          
EOF
        ;;
        "SQLMAP") cat << "EOF"
  _  ___  _    __  __   _   ___ 
 / __|/ _ \| |  |  \/  | /_\ | _ \
 \__ \ (_) | |__| |\/| |/ _ \|  _/
 |___/\__\_\____|_|  |_/_/ \_\_|                               
EOF
        ;;
        "HYDRA") cat << "EOF"
  _  ___   _____  ___    _   
 | || \ \ / /   \| _ \  /_\  
 | __ |\ V /| |) |   / / _ \ 
 |_||_| |_| |___/|_|_\/_/ \_\                             
EOF
        ;;
        "FUFF") cat << "EOF"
  ___ _   _ ___ ___ 
 | __| | | | __| __|
 | _|| |_| | _|| _| 
 |_|  \___/|_| |_|  
EOF
        ;;
    esac
    echo -e "${RESET}"
}

# Setup baseline URL structures
echo "http://$TARGET" > urls.txt
echo "https://$TARGET" >> urls.txt

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
    
        print_hacker_banner "WHATWEB"
        run_with_timeout_skip "whatweb -i urls.txt --log-verbose=\"$OUTDIR/whatweb.txt\"" 180
        
        if [ -n "$DOMAIN_ARG" ]; then
            DOMAIN=$(echo "$DOMAIN_ARG" | tr 'A-Z' 'a-z')
            echo -e "${GREEN}[+] Hardcoded Domain Scope Overridden by Scoping Sheet Target Context: $DOMAIN${RESET}"
        else
            echo "[*] Resolving dynamic domain framework tokens..."
            DOMAIN=$(grep -hviE 'nmap\.org|Nmap|NMAP|example\.com|apache\.org|ubuntu\.com|github\.com' "$OUTDIR/nmap_services.txt" "$OUTDIR/whatweb.txt" 2>/dev/null | grep -oE '[a-zA-Z0-9._-]+\.(local|loca|htb)' | head -n 1)
            if [ -z "$DOMAIN" ]; then
                DOMAIN="inlanefreight.local"
                echo "[!] No domain discovered. Utilizing framework module baseline fallback: $DOMAIN"
            else
                [[ "$DOMAIN" == *".loca" ]] && DOMAIN="${DOMAIN}l"
                echo "[+] Dynamic domain verification successful: $DOMAIN"
            fi
        fi

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
        if grep -qi "80/tcp" "$OUTDIR/nmap_tcp.txt" 2>/dev/null; then
            echo "[*] Launching Nikto on Port 80..."
            run_with_timeout_skip "nikto -h http://$TARGET -nossl -nointeractive -Tuning 123489 -Format txt -output \"$OUTDIR/nikto_http.txt\" -Display 1" 120
        fi
        
        print_hacker_banner "FEROXBUSTER"
        run_with_timeout_skip "feroxbuster -u http://$TARGET --scan-dir-listings -x php,html,txt -o \"$OUTDIR/feroxbuster.txt\"" 300       

        # ==============================================================================
        # SCRAPER HARVESTING CONSOLIDATION BLOCK
        # ==============================================================================
        echo -e "${GREEN}[*] Initiating Scraper Harvesting Engine...${RESET}"
        
        echo "http://$TARGET" > "$TARGETS_LIST"
        echo "http://$TARGET/" >> "$TARGETS_LIST"
        
        if [ -f "$OUTDIR/gobuster_http.txt" ]; then
            grep "Status: 301\|Status: 200" "$OUTDIR/gobuster_http.txt" | awk '{print $1}' | while read -r path; do
                echo "http://$TARGET$path" >> "$TARGETS_LIST"
                if [[ "$path" == *"/monitoring"* ]]; then
                    echo "http://$TARGET/monitoring/login.php" >> "$TARGETS_LIST"
                    echo "http://$TARGET/monitoring/ping.php" >> "$TARGETS_LIST"
                fi
            done
        fi

        if [ -f "$OUTDIR/feroxbuster.txt" ]; then
            sed 's/\x1b\[[0-9;]*m//g' "$OUTDIR/feroxbuster.txt" | grep -oE "http://$TARGET[^[:space:]'\",]+" | tr -d '\r' >> "$TARGETS_LIST"
        fi

        sed -i 's/[[:punct:]]$//g' "$TARGETS_LIST" 2>/dev/null
        sort -u "$TARGETS_LIST" -o "$TARGETS_LIST"
        
        echo "[+] Scraper complete. Clean new-line separated targets saved inside: $TARGETS_LIST"

        # Targeted Bulk SQLMap Verification
        if command -v sqlmap &> /dev/null && [ -s "$TARGETS_LIST" ]; then
            print_hacker_banner "SQLMAP"
            echo "[+] Injecting targets file pool straight into SQLMap bulk verifier engine..."
            run_with_timeout_skip "sqlmap -m \"$TARGETS_LIST\" --batch --random-agent --forms --crawl=1 --level=2 --risk=1 -o \"$OUTDIR/sqlmap_bulk_verify.txt\"" 300
        fi

        # VHost Fuzzing Block
        echo "[*] Detecting standard host size variations..."
        local BASELINE_SIZE=$(curl -s -o /dev/null -D - -H "Host: nonexistentdomain123.$DOMAIN" http://$TARGET | grep -i "Content-Length" | awk '{print $2}' | tr -d '\r')
        [ -z "$BASELINE_SIZE" ] && BASELINE_SIZE="15157"

        local VHOST_WORDLIST="/usr/share/seclists/Discovery/DNS/namelist.txt"
        [ ! -f "$VHOST_WORDLIST" ] && VHOST_WORDLIST="/opt/useful/seclists/Discovery/DNS/namelist.txt"

        if [ -f "$VHOST_WORDLIST" ]; then
            print_hacker_banner "FUFF"
            echo "[+] Fuzzing subdomains via FFUF (Verbose enabled, tracking responses against context: $DOMAIN)..."
            run_with_timeout_skip "ffuf -v -w $VHOST_WORDLIST:FUZZ -u http://$TARGET/ -H 'Host: FUZZ.$DOMAIN' -fs $BASELINE_SIZE -t 40 -timeout 5 -maxtime 60 -r -o \"$OUTDIR/ffuf_vhosts.json\"" 90
            
            if [ -f "$OUTDIR/ffuf_vhosts.json" ]; then
                grep -oE '"value":"[^"]+"' "$OUTDIR/ffuf_vhosts.json" 2>/dev/null | cut -d'"' -f4 | sort -u | awk -v dom="$DOMAIN" '{print $1 "." dom}' >> "$OUTDIR/discovered_hosts.txt"
            fi
        fi

        echo "HTTP scan done!"
    fi

    # FTP (Anonymously mapping and saving files automatically)
    if grep -qi "ftp" "$OUTDIR/nmap_services.txt"; then
        print_hacker_banner "HYDRA"
        echo "[+] FTP detected. Running validation checks..."
        echo -e "open $TARGET\nanonymous\nanonymous\nbin\nls\nget flag.txt $OUTDIR/ftp_flag.txt\nbye" | ftp -n &>/dev/null
        
        if [ -f /usr/share/wordlists/rockyou.txt ]; then
            run_with_timeout_skip "hydra -l anonymous -P /usr/share/wordlists/rockyou.txt -t 4 ftp://$TARGET -o \"$OUTDIR/ftp_hydra.txt\"" 180
        fi
    fi

    # SMB
    if grep -qi "smb" "$OUTDIR/nmap_services.txt" || grep -qi "netbios" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMB detected"
        print_hacker_banner "ENUM4LINUX"
        run_with_timeout_skip "enum4linux -a \"$TARGET\" > \"$OUTDIR/enum4linux.txt\"" 300
        
        if command -v nxc &> /dev/null; then
            print_hacker_banner "NETEXEC"
            run_with_timeout_skip "nxc smb $TARGET --shares > \"$OUTDIR/nxc_shares.txt\"" 180
        fi
    fi

    # SSH (With dynamic lightweight password validation loop)
    if grep -qi "ssh" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SSH detected. Running targeted validation combo pass..."
        run_with_timeout_skip "ssh -v -o BatchMode=yes -o ConnectTimeout=3 user@$TARGET 2>&1 | grep 'SSH-' > \"$OUTDIR/ssh_version.txt\"" 120
        
        # Creating a micro password validation loop mirroring your manual scoping testing checks safely
        echo -e "admin\nroot" > "$OUTDIR/ssh_users.txt"
        echo -e "admin\ntoor\nWelcome\nPass123" > "$OUTDIR/ssh_passwords.txt"
        run_with_timeout_skip "hydra -L $OUTDIR/ssh_users.txt -P $OUTDIR/ssh_passwords.txt -t 4 ssh://$TARGET -o \"$OUTDIR/ssh_targeted_brute.txt\"" 60
        rm -f "$OUTDIR/ssh_users.txt" "$OUTDIR/ssh_passwords.txt"
    fi

    # Email Services (SMTP Open Relay & User enumeration validation loops)
    if grep -qi "smtp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMTP detected. Auditing configuration parameters..."
        
        # Validate for Open Relay vulnerability explicitly using Nmap scripts
        run_with_timeout_skip "nmap -p25 -Pn --script smtp-open-relay $TARGET -oN \"$OUTDIR/smtp_open_relay.txt\"" 120
        
        if [ -f /usr/share/wordlists/usernames.txt ]; then
            print_hacker_banner "SMTP-USER-ENUM"
            echo "[*] Exploiting VRFY parameter mapping vectors..."
            run_with_timeout_skip "smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t $TARGET > \"$OUTDIR/smtp_enum.txt\"" 300
        fi
    fi

    # RPC
    if grep -qi "rpcbind" "$OUTDIR/nmap_services.txt"; then
        echo "[+] RPCbind detected. Extracting portmapper details..."
        run_with_timeout_skip "rpcinfo $TARGET > \"$OUTDIR/rpcinfo.txt\"" 120
    fi

    # DNS
    if grep -qi "domain" "$OUTDIR/nmap_services.txt"; then
        print_hacker_banner "DIG"
        run_with_timeout_skip "dig axfr @$TARGET $DOMAIN > \"$OUTDIR/dns_zone.txt\"" 120
        
        if [ -s "$OUTDIR/dns_zone.txt" ]; then
            grep -E 'IN[[:space:]]+A' "$OUTDIR/dns_zone.txt" | awk '{print $1}' | sed 's/\.$//' | sort -u >> "$OUTDIR/discovered_hosts.txt"
        fi
        
        print_hacker_banner "DNSENUM"
        run_with_timeout_skip "dnsenum --dnsserver $TARGET --enum $DOMAIN > \"$OUTDIR/dnsenum.txt\"" 300
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
                echo "### $service_line" >> "$EXPLOIT_OUT"
                run_with_timeout_skip "searchsploit \"$service_line\" >> \"$EXPLOIT_OUT\"" 60
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
    if command -v wkhtmltopdf &> /dev/null; then
        pandoc "$REPORT_MD" -o "$REPORT_PDF" --metadata title="Recon Report: $TARGET" --pdf-engine=wkhtmltopdf
        echo "[+] PDF report saved to: $REPORT_PDF"
    else
        pandoc "$REPORT_MD" -o "$OUTDIR/report_${TARGET}.html" --metadata title="Recon Report: $TARGET"
        echo "[+] LaTeX engine missing — Saved HTML report to: $OUTDIR/report_${TARGET}.html"
    fi
fi

# Print final etc hosts formatting blocks safely
echo -e "\n${GREEN}[!] LOCAL MACHINE ALIAS MAPPING MANAGER:${RESET}"
echo -e "--------------------------------------------------------"
echo "sudo tee -a /etc/hosts > /dev/null <<EOT"
echo "$TARGET $DOMAIN"
if [ -f "$OUTDIR/discovered_hosts.txt" ]; then
    sort -u "$OUTDIR/discovered_hosts.txt" | while read -r host; do
        if [ "$host" != "$DOMAIN" ] && [ -n "$host" ]; then
            echo "$TARGET $host"
        fi
    done
fi
echo "EOT"
echo -e "--------------------------------------------------------"

echo "[*] Done. All results saved in $OUTDIR/"

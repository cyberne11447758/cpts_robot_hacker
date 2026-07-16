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

    trap 'echo -e "\n[!] Forcefully breaking stuck execution ($pid)..."; kill -9 $pid 2>/dev/null; killall ffuf nikto sqlmap feroxbuster hydra wpscan 2>/dev/null; wait $pid 2>/dev/null; trap - INT; return 130' INT

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

# hacker banner created with font 'Small' https://patorjk.com/software/taag/#p=display&f=Small
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
        "WPSCAN") cat << "EOF"
 __      ___  ___  ___   _   _  _ 
 \ \    / / _ \/ __|/ __| /_\ | \| |
  \ \/\/ /|  _/\__ \ (__ / _ \| .` |
   \_/\_/ |_|  |___/\___/_/ \_\_|\_|
EOF
        ;;
        "ENUM4LINUX") cat << "EOF"
  ___ _  _ _   _ __  __ _ _  _    ___ _  _ _   ___  __
 | __| \| | | | |  \/  | | || |  |_ _| \| | | | \ \/ /
 | _|| .` | |_| | |\/| |_  _| |__ | || .` | |_| |>  < 
 |___|_|\_|\___/|_|  |_| |_||____|___|_|\_|\___//_/\_\
EOF
        ;;
		"PANDOC") cat << "EOF"
 ___  _   _  _ ___   ___   ___ 
| _ \/_\ | \| |   \ / _ \ / __|
|  _/ _ \| .` | |) | (_) | (__ 
|_|/_/ \_\_|\_|___/ \___/ \___|
                                
EOF
        ;;
		"RPCINFO") cat << "EOF"
 ___ ___  ___ ___ _  _ ___ ___  
| _ \ _ \/ __|_ _| \| | __/ _ \ 
|   /   / (__ | || .` | _| (_) |
|_|_\_|  \___|___|_|\_|_| \___/ 
EOF
        ;;
    esac
    echo -e "${RESET}"
}

# Setup baseline URL structures
echo "http://$TARGET" > urls.txt
echo "https://$TARGET" >> urls.txt

# Two-Stage TCP Recon Pipeline
print_hacker_banner "NMAP"
run_with_timeout_skip "nmap -p- -Pn -n --min-rate 5000 -T4 -oN \"$OUTDIR/nmap_tcp.txt\" \"$TARGET\"" 300

TCP_PORTS=$(grep '/tcp' "$OUTDIR/nmap_tcp.txt" | cut -d '/' -f1 | paste -sd ',' -)
if [ -z "$TCP_PORTS" ]; then
    TCP_PORTS="21,22,25,53,80,110,111,143,993,995,8080"
fi

run_with_timeout_skip "nmap -sC -sV -p $TCP_PORTS -oN \"$OUTDIR/nmap_tcp_services.txt\" \"$TARGET\"" 300
run_with_timeout_skip "nmap -sU --top-ports 20 --max-retries 1 -T4 -oN \"$OUTDIR/nmap_udp.txt\" \"$TARGET\"" 120

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
            echo -e "${GREEN}[+] Domain Override Locked: $DOMAIN${RESET}"
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

        if command -v wpscan &> /dev/null; then
            print_hacker_banner "WPSCAN"
            run_with_timeout_skip "wpscan --url http://$TARGET --enumerate vp,vt,tt,cb --detection-mode passive --disable-tls-checks 2>&1 | tee \"$OUTDIR/wpscan_results.txt\"" 120
        fi

        # Consolidated Target Harvesting Scraper Engine
        echo -e "${GREEN}[*] Initiating Scraper Harvesting Engine...${RESET}"
        echo "http://$TARGET" > "$TARGETS_LIST"
        echo "http://$TARGET/" >> "$TARGETS_LIST"
        
        if [ -f "$OUTDIR/gobuster_http.txt" ]; then
            grep "Status: 301\|Status: 200" "$OUTDIR/gobuster_http.txt" | awk '{print $1}' | while read -r path; do
                echo "http://$TARGET$path" >> "$TARGETS_LIST"
            done
        fi

        if [ -f "$OUTDIR/feroxbuster.txt" ]; then
            sed 's/\x1b\[[0-9;]*m//g' "$OUTDIR/feroxbuster.txt" | grep -oE "http://$TARGET[^[:space:]'\",]+" | tr -d '\r' >> "$TARGETS_LIST"
        fi
        sed -i 's/[[:punct:]]$//g' "$TARGETS_LIST" 2>/dev/null
        sort -u "$TARGETS_LIST" -o "$TARGETS_LIST"

        # Targeted Bulk SQLMap Verification
        if command -v sqlmap &> /dev/null && [ -s "$TARGETS_LIST" ]; then
            print_hacker_banner "SQLMAP"
            run_with_timeout_skip "sqlmap -m \"$TARGETS_LIST\" --batch --random-agent --forms --crawl=1 --level=2 --risk=1 -o \"$OUTDIR/sqlmap_bulk_verify.txt\"" 300
        fi

        # Dynamically locates any interactive application login/auth portals fuzzed on the target
        local AUTH_PATH=$(grep -iE 'login|admin|portal|monitoring' "$TARGETS_LIST" | grep -vE '\.(css|js|png|jpg|jpeg|svg|woff)' | head -n 1 | sed "s|http[s]*://$TARGET||g")
        
        if [ -n "$AUTH_PATH" ]; then
            echo -e "${GREEN}[+] Authentication endpoint unmasked dynamically: $AUTH_PATH${RESET}"
            echo -e "admin\nadministrator\nroot" > "$OUTDIR/web_users.txt"
            echo -e "admin\npassword\ntoor\nWelcome\nPass123" > "$OUTDIR/web_passwords.txt"
			print_hacker_banner "HYDRA"
            run_with_timeout_skip "hydra -L $OUTDIR/web_users.txt -P $OUTDIR/web_passwords.txt -t 4 $TARGET http-post-form \"${AUTH_PATH}:username=^USER^&password=^PASS^:F=Failed|Incorrect|Invalid\" 2>&1 | tee \"$OUTDIR/web_login_brute.txt\"" 120
            rm -f "$OUTDIR/web_users.txt" "$OUTDIR/web_passwords.txt"
        fi

        # VHost Fuzzing Block
        echo "[*] Detecting standard host size variations..."
        local BASELINE_SIZE=$(curl -s -o /dev/null -D - -H "Host: nonexistentdomain123.$DOMAIN" http://$TARGET | grep -i "Content-Length" | awk '{print $2}' | tr -d '\r')
        [ -z "$BASELINE_SIZE" ] && BASELINE_SIZE="15157"

        local VHOST_WORDLIST="/usr/share/seclists/Discovery/DNS/namelist.txt"
        [ ! -f "$VHOST_WORDLIST" ] && VHOST_WORDLIST="/opt/useful/seclists/Discovery/DNS/namelist.txt"

        if [ -f "$VHOST_WORDLIST" ]; then
            print_hacker_banner "FUFF"
            run_with_timeout_skip "ffuf -v -w $VHOST_WORDLIST:FUZZ -u http://$TARGET/ -H 'Host: FUZZ.$DOMAIN' -fs $BASELINE_SIZE -t 40 -timeout 5 -r -o \"$OUTDIR/ffuf_vhosts.json\"" 600
            
            if [ -f "$OUTDIR/ffuf_vhosts.json" ] && grep -q '"input"' "$OUTDIR/ffuf_vhosts.json"; then
                grep -oE '"value":"[^"]+"' "$OUTDIR/ffuf_vhosts.json" 2>/dev/null | cut -d'"' -f4 | grep -vE 'http|/|:|[[:space:]]' | sort -u | awk -v dom="$DOMAIN" '{print $1 "." dom}' >> "$OUTDIR/discovered_hosts.txt"
            fi
        fi
        echo "HTTP scan done!"
    fi

    # FTP
    if grep -qi "ftp" "$OUTDIR/nmap_services.txt"; then
        print_hacker_banner "HYDRA"
        echo "[+] FTP detected. Running validation checks..."
        echo -e "open $TARGET\nanonymous\nanonymous\nbin\nls\nget flag.txt $OUTDIR/ftp_flag.txt\nbye" | ftp -n &>/dev/null
        if [ -f /usr/share/wordlists/rockyou.txt ]; then
            run_with_timeout_skip "hydra -l anonymous -P /usr/share/wordlists/rockyou.txt -t 4 ftp://$TARGET 2>&1 | tee \"$OUTDIR/ftp_hydra.txt\"" 180
        fi
    fi

    # SMB
    if grep -qi "smb" "$OUTDIR/nmap_services.txt" || grep -qi "netbios" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMB detected"
        print_hacker_banner "ENUM4LINUX"
        run_with_timeout_skip "enum4linux -a \"$TARGET\" 2>&1 | tee \"$OUTDIR/enum4linux.txt\"" 300
        if command -v nxc &> /dev/null; then
            print_hacker_banner "NETEXEC"
            run_with_timeout_skip "nxc smb $TARGET --shares 2>&1 | tee \"$OUTDIR/nxc_shares.txt\"" 180
        fi
    fi

    # SSH
    if grep -qi "ssh" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SSH detected. Running targeted validation combo pass..."
        run_with_timeout_skip "ssh -v -o BatchMode=yes -o ConnectTimeout=3 user@$TARGET 2>&1 | grep 'SSH-' > \"$OUTDIR/ssh_version.txt\"" 120
        echo -e "admin\nroot" > "$OUTDIR/ssh_users.txt"
        echo -e "admin\ntoor\nWelcome\nPass123" > "$OUTDIR/ssh_passwords.txt"
		print_hacker_banner "HYDRA"
        run_with_timeout_skip "hydra -L $OUTDIR/ssh_users.txt -P $OUTDIR/ssh_passwords.txt -t 4 ssh://$TARGET 2>&1 | tee \"$OUTDIR/ssh_targeted_brute.txt\"" 60
        rm -f "$OUTDIR/ssh_users.txt" "$OUTDIR/ssh_passwords.txt"
    fi

    # Email Services
    if grep -qi "smtp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMTP detected. Auditing configuration parameters..."
		print_hacker_banner "NMAP"
        run_with_timeout_skip "nmap -p25 -Pn --script smtp-open-relay --script-args smtp.timeout=2s $TARGET -oN \"$OUTDIR/smtp_open_relay.txt\"" 120
        
        if [ -f /usr/share/wordlists/usernames.txt ]; then
            print_hacker_banner "SMTP-USER-ENUM"
            run_with_timeout_skip "smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t $TARGET 2>&1 | tee \"$OUTDIR/smtp_enum.txt\"" 180
        fi

        if grep -qiE "imap|pop3" "$OUTDIR/nmap_services.txt"; then
            echo "[*] Mail services exposed. Cross-referencing username hashes via IMAP loop..."
            echo -e "admin\nroot\nsupport" > "$OUTDIR/mail_users.txt"
            echo -e "admin\npassword\ntoor\nWelcome\nPass123" > "$OUTDIR/mail_passwords.txt"
            
            if grep -qi "143/tcp" "$OUTDIR/nmap_services.txt"; then
				print_hacker_banner "HYDRA"
                run_with_timeout_skip "hydra -L $OUTDIR/mail_users.txt -P $OUTDIR/mail_passwords.txt -t 2 imap://$TARGET 2>&1 | tee \"$OUTDIR/imap_login_brute.txt\"" 60
            fi
            rm -f "$OUTDIR/mail_users.txt" "$OUTDIR/mail_passwords.txt"
        fi
    fi

    # RPC
    if grep -qi "rpcbind" "$OUTDIR/nmap_services.txt"; then
        echo "[+] RPCbind detected. Extracting portmapper details..."
		print_hacker_banner "RPCINFO"
        run_with_timeout_skip "rpcinfo $TARGET 2>&1 | tee \"$OUTDIR/rpcinfo.txt\"" 120
    fi

    # DNS
    if grep -qi "domain" "$OUTDIR/nmap_services.txt"; then
        print_hacker_banner "DIG"
        run_with_timeout_skip "dig axfr @$TARGET $DOMAIN 2>&1 | tee \"$OUTDIR/dns_zone.txt\"" 120
        if [ -s "$OUTDIR/dns_zone.txt" ]; then
            grep -E 'IN[[:space:]]+A' "$OUTDIR/dns_zone.txt" | awk '{print $1}' | sed 's/\.$//' | sort -u >> "$OUTDIR/discovered_hosts.txt"
        fi
        print_hacker_banner "DNSENUM"
        run_with_timeout_skip "dnsenum --dnsserver $TARGET --noreverse --enum $DOMAIN 2>&1 | tee \"$OUTDIR/dnsenum.txt\"" 180
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
        echo "[+] HTML report saved to: $OUTDIR/report_${TARGET}.html"
    fi
fi

# Terminal Diagnostic Summary Engine Dashboard
echo -e "\n${GREEN}============================================================================${RESET}"
echo -e "${GREEN}🎯 CRITICAL PENTESTING PATHS & NEXT-STEP ESCALATIONS${RESET}"
echo -e "${GREEN}============================================================================${RESET}"

if [ -f "$OUTDIR/ftp_flag.txt" ]; then
    echo -e "[+] ${GREEN}FTP SERVICE (Port 21):${RESET}"
    echo -e "    --> ATTACK VECTOR: Anonymous FTP login is ENABLED!"
    echo -e "    --> ACTIONABLE: A flag file was located and automatically harvested to: $OUTDIR/ftp_flag.txt\n"
fi

if [ -f "$OUTDIR/smtp_enum.txt" ] && grep -q "VULNERABLE\|root\|data" "$OUTDIR/smtp_enum.txt" 2>/dev/null; then
    echo -e "[+] ${GREEN}SMTP MAIL SERVICE (Port 25):${RESET}"
    echo -e "    --> ATTACK VECTOR: VRFY user enumeration is active."
    echo -e "    --> ACTIONABLE: Valid local server account logs generated inside: $OUTDIR/smtp_enum.txt"
    if [ -f "$OUTDIR/imap_login_brute.txt" ] && grep -qi "login:" "$OUTDIR/imap_login_brute.txt"; then
        echo -e "    --> ATTACK VECTOR: Exposed system mail accounts leaked weak plaintext passwords over IMAP!"
    fi
fi

if [ -f "$OUTDIR/web_login_brute.txt" ] && grep -qi "login:" "$OUTDIR/web_login_brute.txt"; then
    echo -e "[+] ${GREEN}WEB PORTAL AUTHENTICATION SUCCESS (Port 80):${RESET}"
    echo -e "    --> ATTACK VECTOR: Default administrative credentials accepted on a discovered login interface!"
    echo -e "    --> ACTIONABLE: Active access keys saved into: $OUTDIR/web_login_brute.txt\n"
fi

if [ -f "$OUTDIR/wpscan_results.txt" ] && grep -qi "plugins found" "$OUTDIR/wpscan_results.txt"; then
    echo -e "[+] ${GREEN}CONTENT MANAGEMENT INFRASTRUCTURE (Port 80):${RESET}"
    echo -e "    --> ATTACK VECTOR: Active CMS deployment unmasked. Vulnerable components logged to wpscan_results.txt\n"
fi

if [ -f "$OUTDIR/sqlmap_bulk_verify.txt" ]; then
    echo -e "[+] ${GREEN}WEB INFRASTRUCTURE & BULK FORM TESTING SUMMARY RESULTS:${RESET}"
    echo "----------------------------------------------------------------------------"
    printf "    %-56s | %-12s\n" "TARGET URL / PATH" "VULN STATUS"
    echo "----------------------------------------------------------------------------"
    while read -r url; do
        [ -z "$url" ] && continue
        clean_dir=$(echo "$url" | sed -e 's/http[s]*:\/\///g' -e 's/\/.*//g')
        target_log_dir="/root/.local/share/sqlmap/output/$clean_dir"
        [ ! -d "$target_log_dir" ] && target_log_dir="$HOME/.local/share/sqlmap/output/$clean_dir"
        if [ -d "$target_log_dir" ] && [ -s "$target_log_dir/log" ]; then
            if grep -qi "technique" "$target_log_dir/log"; then
                printf "    %-56s | \033[1;32m%12s\033[0m\n" "$url" "VULNERABLE!"
            else
                printf "    %-56s | \033[1;31m%12s\033[0m\n" "$url" "FAILED"
            fi
        else
            printf "    %-56s | %-12s\n" "$url" "SKIPPED"
        fi
    done < "$TARGETS_LIST"
    echo "----------------------------------------------------------------------------"
fi
echo -e "${GREEN}============================================================================${RESET}"

# Print final etc hosts formatting blocks safely
echo -e "\n${GREEN}[!] LOCAL MACHINE ALIAS MAPPING MANAGER:${RESET}"
echo -e "--------------------------------------------------------"
echo "sudo tee -a /etc/hosts > /dev/null <<EOT"
echo "$TARGET $DOMAIN"
if [ -f "$OUTDIR/discovered_hosts.txt" ]; then
    sort -u "$OUTDIR/discovered_hosts.txt" | grep -vE '[0-9]|/|http|-' | while read -r host; do
        if [ "$host" != "$DOMAIN" ] && [ -n "$host" ]; then
            echo "$TARGET $host"
        fi
    done
fi
echo "EOT"
echo -e "--------------------------------------------------------"

echo "[*] Done. All results saved in $OUTDIR/"

#!/bin/bash

# Colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"

# ==============================================================================
# 1. PREVENTATIVE CHECKS & LOCK HANDLING
# ==============================================================================

# Function to wait for background apt/dpkg locks to release
wait_for_apt_locks() {
    echo -e "${BLUE}[*] Checking for background package manager locks...${RESET}"
    local lock_files=("/var/lib/dpkg/lock-frontend" "/var/lib/dpkg/lock" "/var/lib/apt/lists/lock")
    local locked=true

    while [ "$locked" = true ]; do
        locked=false
        for lock in "${lock_files[@]}"; do
            if fuser "$lock" &>/dev/null; then
                echo -e "${YELLOW}[!] Package manager is locked by another process (holding file: $lock).${RESET}"
                echo -e "${YELLOW}[*] Waiting 10 seconds for it to release...${RESET}"
                sleep 10
                locked=true
                break
            fi
        done
    done
    echo -e "${GREEN}[+] Package manager is free to use.${RESET}"
}

# Run the lock check before executing any package management steps
wait_for_apt_locks

# Temporarily disable the broken Microsoft repository to prevent update failure
if ls /etc/apt/sources.list.d/*microsoft*.list &>/dev/null; then
    echo -e "${BLUE}[*] Disabling broken Microsoft repository configuration...${RESET}"
    sudo rename 's/\.list$/\.list\.disabled/' /etc/apt/sources.list.d/*microsoft*.list 2>/dev/null
    echo -e "${GREEN}[+] Microsoft repository disabled.${RESET}"
fi

# ==============================================================================
# 2. UPDATE REPOSITORY LISTS
# ==============================================================================
echo -e "${BLUE}[*] Updating package lists...${RESET}"
if sudo DEBIAN_FRONTEND=noninteractive apt-get -qq update > /dev/null; then
  echo -e "${GREEN}[+] Package lists updated successfully.${RESET}"
else
  echo -e "${RED}[!] Failed to update package lists. Check your internet connection or active repositories.${RESET}"
fi

# NOTE: The full system upgrade ("apt-get upgrade") has been programmatically removed
# to prevent breaking package configurations or hanging on interactive prompts (e.g., Xorg configuration).

# ==============================================================================
# 3. INSTALL REQUIRED PACKAGES
# ==============================================================================
echo -e "${BLUE}[*] Installing required security tools...${RESET}"

REQUIRED_PACKAGES=(
  git nmap whatweb gobuster ffuf hydra ncrack smbclient smbmap snmp 
  ldap-utils rpcbind dnsutils nfs-common ftp gcc make python3-pip 
  nuclei onesixtyone pandoc polenum ssh-audit netexec wpscan sqlmap
)

FAILED_PACKAGES=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
  # Double check check for netexec if apt uses standard nxc or pipx alternative
  if [ "$pkg" = "netexec" ] && (command -v netexec &>/dev/null || command -v nxc &>/dev/null); then
    echo -e "${YELLOW}[*] netexec (nxc) is already installed.${RESET}"
    continue
  fi

  if dpkg -s "$pkg" &>/dev/null; then
    echo -e "${YELLOW}[*] $pkg is already installed.${RESET}"
  else
    echo -e "${BLUE}[*] Installing $pkg...${RESET}"
    # Force strict non-interactive variables and keep older configuration structures
    if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
       -o Dpkg::Options::="--force-confdef" \
       -o Dpkg::Options::="--force-confold" \
       "$pkg" > /dev/null 2>&1; then
      echo -e "${GREEN}[+] Installed $pkg successfully.${RESET}"
    else
      echo -e "${RED}[!] Failed to install $pkg via APT.${RESET}"
      FAILED_PACKAGES+=("$pkg")
    fi
  fi
done

# ==============================================================================
# 4. CRITICAL WORDLIST DEPLOYMENT
# ==============================================================================
echo -e "${BLUE}[*] Setting up default wordlists...${RESET}"
# Extract rockyou.txt if it is compressed
if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    echo -e "${BLUE}[*] Decompressing rockyou.txt.gz...${RESET}"
    sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
fi

# Create a local default usernames list if missing
if [ ! -f /usr/share/wordlists/usernames.txt ]; then
    sudo mkdir -p /usr/share/wordlists
    echo -e "admin\nroot\nuser\nguest\ntest\nadministrator\nsupport" | sudo tee /usr/share/wordlists/usernames.txt > /dev/null
    echo -e "${GREEN}[+] Generated a fallback usernames list at /usr/share/wordlists/usernames.txt${RESET}"
fi

# ==============================================================================
# 5. INTEGRATIONS & FRAMEWORKS
# ==============================================================================

# Metasploit Framework Install
echo -e "${BLUE}[*] Checking for Metasploit Framework...${RESET}"
if command -v msfconsole >/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Metasploit is already installed: $(msfconsole --version 2>&1 | head -1)${RESET}"
else
  echo -e "${BLUE}[*] Installing Metasploit Framework...${RESET}"
  if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y metasploit-framework > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Metasploit Framework installed via apt.${RESET}"
  else
    echo -e "${YELLOW}[*] apt install failed, attempting Rapid7 installer...${RESET}"
    curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/scripts/msfupdate.sh -o msfinstall.sh >/dev/null 2>&1
    chmod +x msfinstall.sh
    sudo DEBIAN_FRONTEND=noninteractive ./msfinstall.sh >/dev/null 2>&1
    rm msfinstall.sh
    if command -v msfconsole >/dev/null 2>&1; then
      echo -e "${GREEN}[+] Metasploit Framework installed successfully via Rapid7 installer.${RESET}"
    else
      echo -e "${RED}[!] Metasploit installation failed.${RESET}"
      FAILED_PACKAGES+=("metasploit-framework")
    fi
  fi
fi

# Rust Toolchain Setup
echo -e "${BLUE}[*] Checking for Rust toolchain...${RESET}"
if command -v rustc >/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Rust is already installed: $(rustc --version)${RESET}"
else
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Rust installed successfully.${RESET}"
  else
    echo -e "${RED}[!] Rust installation failed.${RESET}"
  fi
fi

# GoWitness Check/Install (Using Go compiler if binary missing)
if ! command -v gowitness &>/dev/null; then
    echo -e "${BLUE}[*] GoWitness binary missing. Installing via go/pip/apt fallback...${RESET}"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y gowitness >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}[!] Apt installation for GoWitness failed. Attempting go install...${RESET}"
        if command -v go &>/dev/null; then
            go install github.com/sensepost/gowitness@latest >/dev/null 2>&1
        fi
    fi
fi

# ==============================================================================
# 6. FINALIZE & REMOVE UNUSED PACKAGES
# ==============================================================================
echo -e "${BLUE}[*] Removing unused dependencies...${RESET}"
sudo DEBIAN_FRONTEND=noninteractive apt-get -qq autoremove -y > /dev/null

echo
echo -e "${BLUE}=== Installation Status ===${RESET}"
if [ ${#FAILED_PACKAGES[@]} -eq 0 ]; then
  echo -e "${GREEN}[*] All targeted recon tools are successfully installed and active!${RESET}"
else
  echo -e "${RED}[!] The following packages could not be auto-installed: ${FAILED_PACKAGES[*]}${RESET}"
  echo -e "${YELLOW}[*] Please attempt installing them manually using: sudo apt install <package>${RESET}"
fi
echo
echo -e "${GREEN}[*] Installation script completed successfully.${RESET}"

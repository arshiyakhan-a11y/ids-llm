# shared settings - override by exporting variables before running a script
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE_TX="${IFACE_TX:-veth0}"           # tcpreplay writes here
IFACE_RX="${IFACE_RX:-veth1}"           # Snort + Suricata sniff here
HOME_NET="${HOME_NET:-192.168.10.0/24}" # CICIDS2017 victim LAN
SURICATA_YAML="${SURICATA_YAML:-/etc/suricata/suricata.yaml}"
SNORT_LUA="${SNORT_LUA:-/usr/local/etc/snort/snort.lua}"
SNORT_RULES="${SNORT_RULES:-$ROOT/rules/snort3-community-rules/snort3-community.rules}"
SNORT_FIELDS="seconds timestamp action class dir dst_addr dst_port gid iface msg priority proto rev rule service sid src_addr src_port"
LOG_SURI="$ROOT/logs/suricata"
LOG_SNORT="$ROOT/logs/snort"

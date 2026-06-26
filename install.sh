#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
cyan='\033[0;36m'
plain='\033[0m'

cur_dir=$(pwd)

xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "Failed to check the system OS, please contact the author!" >&2
    exit 1
fi
echo "The OS release is: $release"

arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        armv6* | armv6) echo 'armv6' ;;
        armv5* | armv5) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo -e "${green}Unsupported CPU architecture! ${plain}" && rm -f install.sh && exit 1 ;;
    esac
}

echo "Arch: $(arch)"

if [[ "${XUI_NONINTERACTIVE:-0}" == "1" ]] || [[ ! -t 0 ]]; then
    NONINTERACTIVE=1
else
    NONINTERACTIVE=0
fi
export NONINTERACTIVE

# ============================================================
# SNI SCANNER MODULE
# ============================================================

SNI_RESULTS_FILE="/tmp/xui_sni_results.txt"
SNI_BEST_FILE="/tmp/xui_sni_best.txt"

# بررسی TLS handshake برای یک SNI
check_sni_tls() {
    local host="$1"
    local port="${2:-443}"
    local timeout=5

    local result
    result=$(echo | timeout "$timeout" openssl s_client \
        -connect "${host}:${port}" \
        -servername "$host" \
        -tls1_2 2>&1)

    if echo "$result" | grep -q "Verify return code: 0"; then
        echo "OK"
    elif echo "$result" | grep -q "CONNECTED"; then
        echo "CONNECTED_NO_VERIFY"
    else
        echo "FAIL"
    fi
}

# تست latency یک هاست
check_latency() {
    local host="$1"
    local count=3
    local result

    result=$(ping -c "$count" -W 2 "$host" 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
    if [[ -z "$result" ]]; then
        echo "9999"
    else
        echo "${result%.*}"
    fi
}

# بررسی سازگاری با xray (WebSocket + TLS)
check_xray_compat() {
    local host="$1"
    local timeout=6

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time "$timeout" \
        -H "Host: $host" \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        "https://${host}" 2>/dev/null)

    # کدهای معمول برای سازگاری WS
    case "$http_code" in
        101|200|301|302|400|403|404|426|502|503) echo "COMPAT" ;;
        *) echo "UNKNOWN:${http_code}" ;;
    esac
}

# پیدا کردن Clean IP های Cloudflare
scan_cloudflare_ips() {
    local ranges=(
        "104.16.0.0/12"
        "172.64.0.0/13"
        "162.158.0.0/15"
        "198.41.128.0/17"
        "197.234.240.0/22"
        "190.93.240.0/20"
        "188.114.96.0/20"
        "185.221.208.0/22"
        "108.162.192.0/18"
        "141.101.64.0/18"
    )

    echo -e "${cyan}اسکن Cloudflare Clean IPs...${plain}"
    echo -e "${yellow}این فرآیند ممکنه چند دقیقه طول بکشه${plain}"
    echo ""

    local clean_ips=()
    local tested=0
    local max_test=20  # حداکثر IP برای تست

    > "$SNI_RESULTS_FILE"

    for range in "${ranges[@]}"; do
        # گرفتن چند IP از هر range
        local ips
        ips=$(python3 -c "
import ipaddress, random
net = ipaddress.ip_network('${range}')
hosts = list(net.hosts())
sample = random.sample(hosts, min(3, len(hosts)))
for ip in sample:
    print(str(ip))
" 2>/dev/null)

        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            [[ $tested -ge $max_test ]] && break 2

            printf "  تست IP: %-18s " "$ip"
            tested=$((tested+1))

            # بررسی TLS
            local tls_result
            tls_result=$(check_sni_tls "$ip" 443)

            # بررسی latency
            local latency
            latency=$(check_latency "$ip")

            if [[ "$tls_result" == "OK" || "$tls_result" == "CONNECTED_NO_VERIFY" ]] && [[ "$latency" -lt 300 ]]; then
                echo -e "${green}✓ latency: ${latency}ms${plain}"
                echo "${ip} ${latency}" >> "$SNI_RESULTS_FILE"
                clean_ips+=("$ip")
            else
                echo -e "${red}✗ (TLS:${tls_result}, latency:${latency}ms)${plain}"
            fi
        done <<< "$ips"
    done

    echo ""
    if [[ ${#clean_ips[@]} -gt 0 ]]; then
        echo -e "${green}Clean IP های پیدا شده:${plain}"
        sort -t' ' -k2 -n "$SNI_RESULTS_FILE" | head -10 | while read -r line; do
            local ip lat
            ip=$(echo "$line" | awk '{print $1}')
            lat=$(echo "$line" | awk '{print $2}')
            echo -e "  ${green}${ip}${plain}  (${lat}ms)"
        done
        # بهترین IP
        sort -t' ' -k2 -n "$SNI_RESULTS_FILE" | head -1 | awk '{print $1}' > "$SNI_BEST_FILE"
    else
        echo -e "${yellow}هیچ Clean IP ای پیدا نشد${plain}"
    fi
}

# اسکن SNI برای لیست دامنه‌ها
scan_sni_list() {
    local domains_file="$1"
    local results=()

    echo -e "${cyan}شروع اسکن SNI...${plain}"
    echo ""
    > "$SNI_RESULTS_FILE"

    while IFS= read -r domain || [[ -n "$domain" ]]; do
        [[ -z "$domain" || "$domain" == \#* ]] && continue
        domain="${domain// /}"

        printf "  %-40s " "$domain"

        # TLS handshake
        local tls
        tls=$(check_sni_tls "$domain")

        # Latency
        local lat
        lat=$(check_latency "$domain")

        # Xray compat
        local compat
        compat=$(check_xray_compat "$domain")

        local status_icon="${red}✗${plain}"
        local score=0

        [[ "$tls" == "OK" ]] && score=$((score+40))
        [[ "$tls" == "CONNECTED_NO_VERIFY" ]] && score=$((score+20))
        [[ "$lat" -lt 100 ]] && score=$((score+30))
        [[ "$lat" -lt 200 ]] && score=$((score+15))
        [[ "$compat" == "COMPAT" ]] && score=$((score+30))

        if [[ $score -ge 50 ]]; then
            status_icon="${green}✓${plain}"
            echo "${domain} ${lat} ${score}" >> "$SNI_RESULTS_FILE"
        fi

        echo -e "${status_icon} TLS:${tls} | lat:${lat}ms | xray:${compat} | score:${score}"
    done < "$domains_file"

    echo ""
    echo -e "${cyan}══════ بهترین SNI ها ══════${plain}"
    if [[ -s "$SNI_RESULTS_FILE" ]]; then
        sort -t' ' -k3 -rn "$SNI_RESULTS_FILE" | head -5 | nl | while read -r line; do
            echo -e "  ${green}${line}${plain}"
        done
        sort -t' ' -k3 -rn "$SNI_RESULTS_FILE" | head -1 | awk '{print $1}' > "$SNI_BEST_FILE"
    else
        echo -e "  ${yellow}هیچ SNI مناسبی پیدا نشد${plain}"
    fi
}

# منوی اصلی SNI Scanner
run_sni_scanner() {
    echo ""
    echo -e "${cyan}╔══════════════════════════════════════╗${plain}"
    echo -e "${cyan}║         SNI Scanner Module           ║${plain}"
    echo -e "${cyan}╚══════════════════════════════════════╝${plain}"
    echo ""
    echo -e "  ${green}1.${plain} اسکن دامنه‌های Cloudflare (Clean IP)"
    echo -e "  ${green}2.${plain} اسکن لیست دامنه‌های سفارشی"
    echo -e "  ${green}3.${plain} تست سریع یک دامنه"
    echo -e "  ${green}0.${plain} بازگشت"
    echo ""
    read -rp "انتخاب: " sni_choice

    case "$sni_choice" in
        1)
            scan_cloudflare_ips
            if [[ -s "$SNI_BEST_FILE" ]]; then
                local best_ip
                best_ip=$(cat "$SNI_BEST_FILE")
                echo ""
                echo -e "${green}بهترین IP: ${best_ip}${plain}"
                read -rp "آیا می‌خواید این IP را در inbound جدید استفاده کنید? [y/n]: " use_it
                if [[ "$use_it" == "y" || "$use_it" == "Y" ]]; then
                    echo "$best_ip" > /tmp/xui_selected_sni.txt
                    echo -e "${green}IP ذخیره شد: ${best_ip}${plain}"
                fi
            fi
            ;;
        2)
            echo -e "${yellow}لیست دامنه‌ها را وارد کنید (هر دامنه یک خط، خالی برای پایان):${plain}"
            local tmpfile
            tmpfile=$(mktemp)
            while IFS= read -rp "> " line; do
                [[ -z "$line" ]] && break
                echo "$line" >> "$tmpfile"
            done
            if [[ -s "$tmpfile" ]]; then
                scan_sni_list "$tmpfile"
                if [[ -s "$SNI_BEST_FILE" ]]; then
                    local best
                    best=$(cat "$SNI_BEST_FILE")
                    echo ""
                    echo -e "${green}بهترین SNI: ${best}${plain}"
                    read -rp "در inbound جدید استفاده شود? [y/n]: " use_it
                    [[ "$use_it" == "y" || "$use_it" == "Y" ]] && echo "$best" > /tmp/xui_selected_sni.txt
                fi
            fi
            rm -f "$tmpfile"
            ;;
        3)
            read -rp "دامنه یا IP را وارد کنید: " test_host
            test_host="${test_host// /}"
            if [[ -n "$test_host" ]]; then
                echo ""
                echo -e "${cyan}در حال تست ${test_host}...${plain}"
                echo -e "  TLS Handshake:  $(check_sni_tls "$test_host")"
                echo -e "  Latency:        $(check_latency "$test_host")ms"
                echo -e "  Xray Compat:    $(check_xray_compat "$test_host")"
            fi
            ;;
        0) return ;;
        *) echo -e "${red}گزینه نامعتبر${plain}" ;;
    esac
}

# ============================================================
# MULTI-ADMIN MANAGEMENT MODULE
# ============================================================

ADMIN_CONFIG_FILE="/etc/x-ui/admins.conf"
ADMIN_LOG_FILE="/var/log/x-ui/admin-access.log"

# ساختار admins.conf:
# username:hashed_password:role:allowed_ips:api_token:created_at:last_login
# role: superadmin | admin | readonly | inbound_only

init_admin_system() {
    install -d -m 750 /etc/x-ui 2>/dev/null
    install -d -m 750 /var/log/x-ui 2>/dev/null

    if [[ ! -f "$ADMIN_CONFIG_FILE" ]]; then
        touch "$ADMIN_CONFIG_FILE"
        chmod 600 "$ADMIN_CONFIG_FILE"
        echo -e "${green}سیستم مدیریت ادمین راه‌اندازی شد${plain}"
    fi
}

hash_password() {
    local pass="$1"
    echo -n "$pass" | openssl dgst -sha256 -hmac "xui-admin-salt-$(hostname)" | awk '{print $2}'
}

gen_api_token() {
    openssl rand -hex 32
}

# نمایش نقش‌های موجود
show_roles() {
    echo ""
    echo -e "${cyan}نقش‌های موجود:${plain}"
    echo -e "  ${green}1. superadmin${plain}  - دسترسی کامل (معادل ادمین اصلی)"
    echo -e "  ${green}2. admin${plain}       - مدیریت inbound ها و کلاینت‌ها"
    echo -e "  ${green}3. readonly${plain}    - فقط مشاهده (بدون تغییر)"
    echo -e "  ${green}4. inbound_only${plain} - فقط مدیریت inbound های خودش"
    echo ""
}

# اضافه کردن ادمین جدید
add_admin() {
    init_admin_system
    echo ""
    echo -e "${cyan}══════ اضافه کردن ادمین جدید ══════${plain}"

    # نام کاربری
    local username=""
    while [[ -z "$username" ]]; do
        read -rp "نام کاربری: " username
        username="${username// /}"
        if [[ -z "$username" ]]; then
            echo -e "${red}نام کاربری نمی‌تواند خالی باشد${plain}"
            continue
        fi
        # بررسی تکراری نبودن
        if grep -q "^${username}:" "$ADMIN_CONFIG_FILE" 2>/dev/null; then
            echo -e "${red}این نام کاربری قبلاً ثبت شده${plain}"
            username=""
        fi
    done

    # پسورد
    local password=""
    while [[ -z "$password" ]]; do
        read -rsp "پسورد: " password
        echo ""
        if [[ ${#password} -lt 8 ]]; then
            echo -e "${red}پسورد باید حداقل ۸ کاراکتر باشد${plain}"
            password=""
            continue
        fi
        local pass_confirm=""
        read -rsp "تکرار پسورد: " pass_confirm
        echo ""
        if [[ "$password" != "$pass_confirm" ]]; then
            echo -e "${red}پسوردها مطابقت ندارند${plain}"
            password=""
        fi
    done

    # نقش
    show_roles
    local role=""
    while [[ -z "$role" ]]; do
        read -rp "نقش (1-4): " role_choice
        case "$role_choice" in
            1) role="superadmin" ;;
            2) role="admin" ;;
            3) role="readonly" ;;
            4) role="inbound_only" ;;
            *) echo -e "${red}گزینه نامعتبر${plain}"; role="" ;;
        esac
    done

    # محدودیت IP (اختیاری)
    local allowed_ips="*"
    read -rp "IP های مجاز (خالی = همه، مثال: 1.2.3.4,5.6.7.8): " ip_input
    if [[ -n "${ip_input// /}" ]]; then
        allowed_ips="${ip_input// /}"
    fi

    # تولید API token
    local api_token
    api_token=$(gen_api_token)

    # هش پسورد
    local hashed_pass
    hashed_pass=$(hash_password "$password")

    # ذخیره
    local created_at
    created_at=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${username}:${hashed_pass}:${role}:${allowed_ips}:${api_token}:${created_at}:never" >> "$ADMIN_CONFIG_FILE"

    echo ""
    echo -e "${green}╔══════════════════════════════════════════╗${plain}"
    echo -e "${green}║     ادمین جدید با موفقیت اضافه شد      ║${plain}"
    echo -e "${green}╚══════════════════════════════════════════╝${plain}"
    echo -e "  ${green}نام کاربری:${plain}  $username"
    echo -e "  ${green}نقش:${plain}         $role"
    echo -e "  ${green}IP های مجاز:${plain} $allowed_ips"
    echo -e "  ${green}API Token:${plain}   $api_token"
    echo -e "${yellow}⚠ API Token را ذخیره کنید — دیگر نمایش داده نمی‌شود${plain}"
    echo ""

    # ثبت لاگ
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ADMIN_CREATED: $username (role: $role)" >> "$ADMIN_LOG_FILE"
}

# لیست ادمین‌ها
list_admins() {
    init_admin_system
    echo ""
    echo -e "${cyan}══════ لیست ادمین‌ها ══════${plain}"

    if [[ ! -s "$ADMIN_CONFIG_FILE" ]]; then
        echo -e "${yellow}هیچ ادمینی ثبت نشده${plain}"
        return
    fi

    printf "  %-20s %-15s %-20s %-25s\n" "نام کاربری" "نقش" "IP های مجاز" "آخرین ورود"
    echo "  ─────────────────────────────────────────────────────────────────────"
    while IFS=: read -r uname _pass role ips _token created last_login; do
        printf "  %-20s %-15s %-20s %-25s\n" "$uname" "$role" "$ips" "$last_login"
    done < "$ADMIN_CONFIG_FILE"
    echo ""
}

# ویرایش ادمین
edit_admin() {
    init_admin_system
    list_admins

    read -rp "نام کاربری ادمین برای ویرایش: " target_user
    target_user="${target_user// /}"

    if ! grep -q "^${target_user}:" "$ADMIN_CONFIG_FILE" 2>/dev/null; then
        echo -e "${red}ادمین پیدا نشد${plain}"
        return 1
    fi

    echo ""
    echo -e "  ${green}1.${plain} تغییر پسورد"
    echo -e "  ${green}2.${plain} تغییر نقش"
    echo -e "  ${green}3.${plain} تغییر IP های مجاز"
    echo -e "  ${green}4.${plain} تولید API Token جدید"
    echo -e "  ${green}0.${plain} بازگشت"
    echo ""
    read -rp "انتخاب: " edit_choice

    local tmpfile
    tmpfile=$(mktemp)

    case "$edit_choice" in
        1)
            local new_pass=""
            while [[ -z "$new_pass" ]]; do
                read -rsp "پسورد جدید: " new_pass
                echo ""
                [[ ${#new_pass} -lt 8 ]] && echo -e "${red}حداقل ۸ کاراکتر${plain}" && new_pass="" && continue
                local confirm=""
                read -rsp "تکرار: " confirm
                echo ""
                [[ "$new_pass" != "$confirm" ]] && echo -e "${red}مطابقت ندارد${plain}" && new_pass=""
            done
            local new_hash
            new_hash=$(hash_password "$new_pass")
            awk -F: -v u="$target_user" -v h="$new_hash" 'BEGIN{OFS=":"} $1==u{$2=h} {print}' \
                "$ADMIN_CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$ADMIN_CONFIG_FILE"
            echo -e "${green}پسورد تغییر کرد${plain}"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] PASSWORD_CHANGED: $target_user" >> "$ADMIN_LOG_FILE"
            ;;
        2)
            show_roles
            read -rp "نقش جدید (1-4): " role_choice
            local new_role=""
            case "$role_choice" in
                1) new_role="superadmin" ;;
                2) new_role="admin" ;;
                3) new_role="readonly" ;;
                4) new_role="inbound_only" ;;
                *) echo -e "${red}نامعتبر${plain}"; rm -f "$tmpfile"; return ;;
            esac
            awk -F: -v u="$target_user" -v r="$new_role" 'BEGIN{OFS=":"} $1==u{$3=r} {print}' \
                "$ADMIN_CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$ADMIN_CONFIG_FILE"
            echo -e "${green}نقش به $new_role تغییر کرد${plain}"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ROLE_CHANGED: $target_user -> $new_role" >> "$ADMIN_LOG_FILE"
            ;;
        3)
            read -rp "IP های جدید (خالی = همه): " new_ips
            new_ips="${new_ips// /}"
            [[ -z "$new_ips" ]] && new_ips="*"
            awk -F: -v u="$target_user" -v ips="$new_ips" 'BEGIN{OFS=":"} $1==u{$4=ips} {print}' \
                "$ADMIN_CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$ADMIN_CONFIG_FILE"
            echo -e "${green}IP های مجاز بروز شد${plain}"
            ;;
        4)
            local new_token
            new_token=$(gen_api_token)
            awk -F: -v u="$target_user" -v t="$new_token" 'BEGIN{OFS=":"} $1==u{$5=t} {print}' \
                "$ADMIN_CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$ADMIN_CONFIG_FILE"
            echo -e "${green}API Token جدید: ${new_token}${plain}"
            echo -e "${yellow}⚠ این token را ذخیره کنید${plain}"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] TOKEN_REGENERATED: $target_user" >> "$ADMIN_LOG_FILE"
            ;;
        0) rm -f "$tmpfile"; return ;;
    esac

    chmod 600 "$ADMIN_CONFIG_FILE"
    rm -f "$tmpfile"
}

# حذف ادمین
remove_admin() {
    init_admin_system
    list_admins

    read -rp "نام کاربری برای حذف: " target_user
    target_user="${target_user// /}"

    if ! grep -q "^${target_user}:" "$ADMIN_CONFIG_FILE" 2>/dev/null; then
        echo -e "${red}ادمین پیدا نشد${plain}"
        return 1
    fi

    read -rp "آیا مطمئنید؟ [y/n]: " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        local tmpfile
        tmpfile=$(mktemp)
        grep -v "^${target_user}:" "$ADMIN_CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$ADMIN_CONFIG_FILE"
        chmod 600 "$ADMIN_CONFIG_FILE"
        echo -e "${green}ادمین $target_user حذف شد${plain}"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ADMIN_REMOVED: $target_user" >> "$ADMIN_LOG_FILE"
    else
        echo -e "${yellow}لغو شد${plain}"
    fi
}

# احراز هویت ادمین با API Token
verify_admin_token() {
    local token="$1"
    local required_role="${2:-readonly}"

    if [[ ! -f "$ADMIN_CONFIG_FILE" ]]; then
        echo "UNAUTHORIZED"
        return 1
    fi

    while IFS=: read -r uname _pass role _ips api_token _created _last; do
        if [[ "$api_token" == "$token" ]]; then
            # بررسی نقش
            local authorized=0
            case "$required_role" in
                readonly) authorized=1 ;;
                inbound_only)
                    [[ "$role" == "inbound_only" || "$role" == "admin" || "$role" == "superadmin" ]] && authorized=1
                    ;;
                admin)
                    [[ "$role" == "admin" || "$role" == "superadmin" ]] && authorized=1
                    ;;
                superadmin)
                    [[ "$role" == "superadmin" ]] && authorized=1
                    ;;
            esac

            if [[ $authorized -eq 1 ]]; then
                # بروزرسانی آخرین ورود
                local tmpfile
                tmpfile=$(mktemp)
                local now
                now=$(date '+%Y-%m-%d %H:%M:%S')
                awk -F: -v u="$uname" -v t="$now" 'BEGIN{OFS=":"} $1==u{$7=t} {print}' \
                    "$ADMIN_CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$ADMIN_CONFIG_FILE"
                chmod 600 "$ADMIN_CONFIG_FILE"
                echo "AUTHORIZED:${uname}:${role}"
                return 0
            else
                echo "FORBIDDEN:${uname}:${role}"
                return 1
            fi
        fi
    done < "$ADMIN_CONFIG_FILE"

    echo "UNAUTHORIZED"
    return 1
}

# منوی مدیریت ادمین
manage_admins_menu() {
    while true; do
        echo ""
        echo -e "${cyan}╔══════════════════════════════════════╗${plain}"
        echo -e "${cyan}║      مدیریت ادمین‌ها                ║${plain}"
        echo -e "${cyan}╚══════════════════════════════════════╝${plain}"
        echo ""
        echo -e "  ${green}1.${plain} اضافه کردن ادمین جدید"
        echo -e "  ${green}2.${plain} لیست ادمین‌ها"
        echo -e "  ${green}3.${plain} ویرایش ادمین"
        echo -e "  ${green}4.${plain} حذف ادمین"
        echo -e "  ${green}5.${plain} نمایش لاگ دسترسی‌ها"
        echo -e "  ${green}6.${plain} تست API Token"
        echo -e "  ${green}0.${plain} بازگشت"
        echo ""
        read -rp "انتخاب: " admin_choice

        case "$admin_choice" in
            1) add_admin ;;
            2) list_admins ;;
            3) edit_admin ;;
            4) remove_admin ;;
            5)
                echo ""
                echo -e "${cyan}══════ لاگ دسترسی‌ها (۲۰ مورد اخیر) ══════${plain}"
                tail -20 "$ADMIN_LOG_FILE" 2>/dev/null || echo -e "${yellow}لاگی موجود نیست${plain}"
                ;;
            6)
                read -rp "API Token: " test_token
                local result
                result=$(verify_admin_token "$test_token" "readonly")
                if [[ "$result" == AUTHORIZED* ]]; then
                    local uname role
                    uname=$(echo "$result" | cut -d: -f2)
                    role=$(echo "$result" | cut -d: -f3)
                    echo -e "${green}✓ معتبر - کاربر: $uname، نقش: $role${plain}"
                elif [[ "$result" == FORBIDDEN* ]]; then
                    echo -e "${yellow}⚠ Token معتبر ولی دسترسی کافی ندارد${plain}"
                else
                    echo -e "${red}✗ Token نامعتبر${plain}"
                fi
                ;;
            0) break ;;
            *) echo -e "${red}گزینه نامعتبر${plain}" ;;
        esac
    done
}

# ============================================================
# INBOUND BUILDER با SNI Integration
# ============================================================

build_inbound_with_sni() {
    echo ""
    echo -e "${cyan}╔══════════════════════════════════════════╗${plain}"
    echo -e "${cyan}║    ساخت Inbound با SNI Scanner          ║${plain}"
    echo -e "${cyan}╚══════════════════════════════════════════╝${plain}"
    echo ""

    # انتخاب پروتکل
    echo -e "  پروتکل:"
    echo -e "  ${green}1.${plain} VLESS + WS + TLS"
    echo -e "  ${green}2.${plain} VMess + WS + TLS"
    echo -e "  ${green}3.${plain} Trojan + TCP + TLS"
    echo -e "  ${green}4.${plain} VLESS + Reality"
    read -rp "انتخاب [1]: " proto_choice
    proto_choice="${proto_choice:-1}"

    # تنظیمات پایه
    local port=""
    while [[ -z "$port" ]]; do
        read -rp "پورت inbound: " port
        port="${port// /}"
        if ! [[ "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
            echo -e "${red}پورت نامعتبر${plain}"
            port=""
        fi
    done

    # SNI Scanner
    local sni_host=""
    echo ""
    echo -e "${yellow}آیا می‌خواید از SNI Scanner برای پیدا کردن بهترین SNI استفاده کنید? [y/n]: ${plain}"
    read -rp "> " use_scanner

    if [[ "$use_scanner" == "y" || "$use_scanner" == "Y" ]]; then
        run_sni_scanner
        if [[ -f /tmp/xui_selected_sni.txt ]]; then
            sni_host=$(cat /tmp/xui_selected_sni.txt)
            echo -e "${green}SNI انتخاب شده: ${sni_host}${plain}"
        fi
        if [[ -z "$sni_host" ]] && [[ -f "$SNI_BEST_FILE" ]]; then
            sni_host=$(cat "$SNI_BEST_FILE")
            echo -e "${green}بهترین SNI از اسکن: ${sni_host}${plain}"
        fi
    fi

    # اگر SNI هنوز خالیه
    if [[ -z "$sni_host" ]]; then
        read -rp "SNI/Host را وارد کنید: " sni_host
        sni_host="${sni_host// /}"
    fi

    # تنظیمات SSL
    local cert_file=""
    local key_file=""
    if [[ "$proto_choice" != "4" ]]; then
        echo ""
        echo -e "  مسیر فایل‌های SSL:"
        read -rp "  Certificate (.pem): " cert_file
        read -rp "  Private Key (.pem): " key_file
    fi

    # UUID برای VLESS/VMess
    local uuid
    uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)/\1-\2-\3-\4-/')

    # ساخت کانفیگ xray JSON
    local inbound_json=""
    case "$proto_choice" in
        1)  # VLESS + WS + TLS
            inbound_json=$(cat <<EOF
{
  "listen": "0.0.0.0",
  "port": ${port},
  "protocol": "vless",
  "settings": {
    "clients": [],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "ws",
    "security": "tls",
    "tlsSettings": {
      "serverName": "${sni_host}",
      "certificates": [
        {
          "certificateFile": "${cert_file}",
          "keyFile": "${key_file}"
        }
      ]
    },
    "wsSettings": {
      "path": "/$(openssl rand -hex 4)",
      "headers": {
        "Host": "${sni_host}"
      }
    }
  },
  "sniffing": {
    "enabled": true,
    "destOverride": ["http","tls"]
  }
}
EOF
)
            ;;
        2)  # VMess + WS + TLS
            inbound_json=$(cat <<EOF
{
  "listen": "0.0.0.0",
  "port": ${port},
  "protocol": "vmess",
  "settings": {
    "clients": []
  },
  "streamSettings": {
    "network": "ws",
    "security": "tls",
    "tlsSettings": {
      "serverName": "${sni_host}",
      "certificates": [
        {
          "certificateFile": "${cert_file}",
          "keyFile": "${key_file}"
        }
      ]
    },
    "wsSettings": {
      "path": "/$(openssl rand -hex 4)",
      "headers": {
        "Host": "${sni_host}"
      }
    }
  }
}
EOF
)
            ;;
        3)  # Trojan + TLS
            inbound_json=$(cat <<EOF
{
  "listen": "0.0.0.0",
  "port": ${port},
  "protocol": "trojan",
  "settings": {
    "clients": []
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "${sni_host}",
      "certificates": [
        {
          "certificateFile": "${cert_file}",
          "keyFile": "${key_file}"
        }
      ]
    }
  }
}
EOF
)
            ;;
        4)  # VLESS + Reality
            local reality_dest="${sni_host}:443"
            [[ -z "$sni_host" ]] && reality_dest="www.google.com:443"

            local reality_private_key
            reality_private_key=$(${xui_folder}/x-ui 2>/dev/null | grep -o 'PrivateKey.*' | head -1 || openssl rand -hex 32)

            inbound_json=$(cat <<EOF
{
  "listen": "0.0.0.0",
  "port": ${port},
  "protocol": "vless",
  "settings": {
    "clients": [],
    "decryption": "none",
    "fallbacks": []
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "dest": "${reality_dest}",
      "xver": 0,
      "serverNames": ["${sni_host:-www.google.com}"],
      "privateKey": "",
      "shortIds": ["$(openssl rand -hex 4)"]
    }
  }
}
EOF
)
            ;;
    esac

    # ذخیره کانفیگ
    local config_dir="/etc/x-ui/inbounds"
    mkdir -p "$config_dir"
    local config_file="${config_dir}/inbound_${port}.json"
    echo "$inbound_json" > "$config_file"
    chmod 600 "$config_file"

    echo ""
    echo -e "${green}╔══════════════════════════════════════════╗${plain}"
    echo -e "${green}║     Inbound با موفقیت ایجاد شد         ║${plain}"
    echo -e "${green}╚══════════════════════════════════════════╝${plain}"
    echo -e "  ${green}پورت:${plain}   $port"
    echo -e "  ${green}SNI:${plain}    $sni_host"
    echo -e "  ${green}UUID:${plain}   $uuid"
    echo -e "  ${green}فایل:${plain}   $config_file"
    echo ""

    # اعمال به پنل از طریق API
    local panel_port
    panel_port=$(${xui_folder}/x-ui setting -show true 2>/dev/null | grep -Eo 'port: .+' | awk '{print $2}')
    local api_token
    api_token=$(${xui_folder}/x-ui setting -getApiToken true 2>/dev/null | grep -Eo 'apiToken: .+' | awk '{print $2}')

    if [[ -n "$panel_port" && -n "$api_token" ]]; then
        echo -e "${yellow}در حال اعمال inbound به پنل...${plain}"
        local response
        response=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -H "X-API-Token: ${api_token}" \
            -d "$inbound_json" \
            "http://127.0.0.1:${panel_port}/api/inbounds/add" 2>/dev/null)

        if echo "$response" | grep -q '"success":true'; then
            echo -e "${green}✓ Inbound به پنل اضافه شد${plain}"
        else
            echo -e "${yellow}⚠ اعمال خودکار انجام نشد — فایل JSON در ${config_file} ذخیره شد${plain}"
            echo -e "${yellow}  می‌توانید آن را از پنل import کنید${plain}"
        fi
    fi
}

# ============================================================
# منوی اصلی x-ui (اضافه شده به منوی موجود)
# ============================================================

show_extended_menu() {
    echo ""
    echo -e "${cyan}╔══════════════════════════════════════════╗${plain}"
    echo -e "${cyan}║     قابلیت‌های اضافه شده به 3x-ui      ║${plain}"
    echo -e "${cyan}╚══════════════════════════════════════════╝${plain}"
    echo ""
    echo -e "  ${green}1.${plain} SNI Scanner"
    echo -e "  ${green}2.${plain} مدیریت ادمین‌ها"
    echo -e "  ${green}3.${plain} ساخت Inbound با SNI Scanner"
    echo -e "  ${green}0.${plain} خروج"
    echo ""
    read -rp "انتخاب: " main_choice

    case "$main_choice" in
        1) run_sni_scanner ;;
        2) manage_admins_menu ;;
        3) build_inbound_with_sni ;;
        0) exit 0 ;;
        *) echo -e "${red}گزینه نامعتبر${plain}" ;;
    esac
}

# ============================================================
# توابع اصلی نصب (از اسکریپت اصلی)
# ============================================================

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 0 || return 1
}
is_ipv6() {
    [[ "$1" =~ : ]] && return 0 || return 1
}
is_ip() {
    is_ipv4 "$1" || is_ipv6 "$1"
}
is_domain() {
    [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+(xn--[a-z0-9]{2,}|[A-Za-z]{2,})$ ]] && return 0 || return 1
}

acme_listen_flag() {
    if ip -4 addr show scope global 2>/dev/null | grep -q "inet "; then
        echo ""
    else
        echo "--listen-v6"
    fi
}

is_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -lnt 2>/dev/null | awk -v p=":${port} " '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:${port} -sTCP:LISTEN >/dev/null 2>&1 && return 0
    fi
    return 1
}

install_base() {
    case "${release}" in
        ubuntu | debian | armbian)
            apt-get update && apt-get install -y -q cron curl tar tzdata socat ca-certificates openssl
            ;;
        fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
            dnf -y update && dnf install -y -q cronie curl tar tzdata socat ca-certificates openssl
            ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then
                yum -y update && yum install -y cronie curl tar tzdata socat ca-certificates openssl
            else
                dnf -y update && dnf install -y -q cronie curl tar tzdata socat ca-certificates openssl
            fi
            ;;
        arch | manjaro | parch)
            pacman -Syu && pacman -Syu --noconfirm cronie curl tar tzdata socat ca-certificates openssl
            ;;
        opensuse-tumbleweed | opensuse-leap)
            zypper refresh && zypper -q install -y cron curl tar timezone socat ca-certificates openssl
            ;;
        alpine)
            apk update && apk add dcron curl tar tzdata socat ca-certificates openssl
            ;;
        *)
            apt-get update && apt-get install -y -q cron curl tar tzdata socat ca-certificates openssl
            ;;
    esac
}

gen_random_string() {
    local length="$1"
    openssl rand -base64 $((length * 2)) \
        | tr -dc 'a-zA-Z0-9' \
        | head -c "$length"
}

prompt_or_default() {
    local __var="$1" __prompt="$2" __default="$3" __env="${4:-$1}"
    if [[ "$NONINTERACTIVE" == "1" ]]; then
        printf -v "$__var" '%s' "${!__env:-$__default}"
    else
        read -rp "$__prompt" "$__var"
    fi
}

write_install_result() {
    local u="$1" p="$2" port="$3" wbp="$4" scheme="$5" host="$6" token="$7" dbtype="$8"
    local result_file="/etc/x-ui/install-result.env"
    local url_host="${host:-SERVER_IP_UNKNOWN}"
    install -d -m 755 /etc/x-ui 2>/dev/null
    local prev_umask
    prev_umask=$(umask)
    umask 077
    {
        printf 'XUI_USERNAME=%q\n' "$u"
        printf 'XUI_PASSWORD=%q\n' "$p"
        printf 'XUI_PANEL_PORT=%q\n' "$port"
        printf 'XUI_WEB_BASE_PATH=%q\n' "$wbp"
        printf 'XUI_ACCESS_URL=%q\n' "${scheme}://${url_host}:${port}/${wbp}"
        printf 'XUI_API_TOKEN=%q\n' "$token"
        printf 'XUI_DB_TYPE=%q\n' "$dbtype"
    } > "$result_file"
    umask "$prev_umask"
    chmod 600 "$result_file" 2>/dev/null
    chown root:root "$result_file" 2>/dev/null || true
    echo -e "${green}Install result written to ${result_file} (mode 600).${plain}"
}

install_acme() {
    echo -e "${green}Installing acme.sh for SSL certificate management...${plain}"
    cd ~ || return 1
    curl -s https://get.acme.sh | sh >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${red}Failed to install acme.sh${plain}"
        return 1
    fi
    echo -e "${green}acme.sh installed successfully${plain}"
    return 0
}

setup_ssl_certificate() {
    local domain="$1"
    local server_ip="$2"

    echo -e "${green}Setting up SSL certificate...${plain}"

    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        install_acme
        [ $? -ne 0 ] && return 1
    fi

    local certPath="/root/cert/${domain}"
    mkdir -p "$certPath"

    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force >/dev/null 2>&1
    ~/.acme.sh/acme.sh --issue -d ${domain} $(acme_listen_flag) --standalone --httpport 80 --force

    if [ $? -ne 0 ]; then
        echo -e "${yellow}Failed to issue certificate for ${domain}${plain}"
        return 1
    fi

    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem \
        --reloadcmd "systemctl restart x-ui" >/dev/null 2>&1

    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
    chmod 600 $certPath/privkey.pem 2>/dev/null
    chmod 644 $certPath/fullchain.pem 2>/dev/null

    local webCertFile="/root/cert/${domain}/fullchain.pem"
    local webKeyFile="/root/cert/${domain}/privkey.pem"

    if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
        ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile" >/dev/null 2>&1
        echo -e "${green}SSL certificate installed and configured successfully!${plain}"
        return 0
    fi
    return 1
}

setup_ip_certificate() {
    local ipv4="$1"
    local ipv6="$2"

    echo -e "${green}Setting up Let's Encrypt IP certificate...${plain}"

    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        install_acme
        [ $? -ne 0 ] && return 1
    fi

    [[ -z "$ipv4" ]] || ! is_ipv4 "$ipv4" && { echo -e "${red}Invalid IPv4${plain}"; return 1; }

    local certDir="/root/cert/ip"
    mkdir -p "$certDir"

    local domain_args="-d ${ipv4}"
    [[ -n "$ipv6" ]] && is_ipv6 "$ipv6" && domain_args="${domain_args} -d ${ipv6}"

    local WebPort="80"
    prompt_or_default WebPort "Port for ACME HTTP-01 listener (default 80): " "80" XUI_ACME_HTTP_PORT
    WebPort="${WebPort:-80}"

    while is_port_in_use "${WebPort}"; do
        echo -e "${yellow}Port ${WebPort} is in use.${plain}"
        [[ "$NONINTERACTIVE" == "1" ]] && return 1
        read -rp "Enter another port: " WebPort
        [[ -z "$WebPort" ]] && return 1
    done

    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force >/dev/null 2>&1
    [[ -n "${XUI_ACME_EMAIL:-}" ]] && ~/.acme.sh/acme.sh --register-account -m "${XUI_ACME_EMAIL}" >/dev/null 2>&1

    ~/.acme.sh/acme.sh --issue \
        ${domain_args} \
        --standalone \
        --server letsencrypt \
        --certificate-profile shortlived \
        --days 6 \
        --httpport ${WebPort} \
        --force

    [ $? -ne 0 ] && return 1

    ~/.acme.sh/acme.sh --installcert -d ${ipv4} \
        --key-file "${certDir}/privkey.pem" \
        --fullchain-file "${certDir}/fullchain.pem" \
        --reloadcmd "systemctl restart x-ui 2>/dev/null || true" 2>&1 || true

    [[ ! -f "${certDir}/fullchain.pem" || ! -f "${certDir}/privkey.pem" ]] && return 1

    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
    chmod 600 ${certDir}/privkey.pem 2>/dev/null
    chmod 644 ${certDir}/fullchain.pem 2>/dev/null

    ${xui_folder}/x-ui cert -webCert "${certDir}/fullchain.pem" -webCertKey "${certDir}/privkey.pem"
    echo -e "${green}IP certificate installed successfully!${plain}"
    return 0
}

ssl_cert_issue() {
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep 'webBasePath:' | awk -F': ' '{print $2}' | tr -d '[:space:]' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep 'port:' | awk -F': ' '{print $2}' | tr -d '[:space:]')

    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        cd ~ || return 1
        curl -s https://get.acme.sh | sh
        [ $? -ne 0 ] && return 1
    fi

    local domain=""
    if [[ "$NONINTERACTIVE" == "1" ]]; then
        domain="${XUI_DOMAIN// /}"
        [[ -z "$domain" ]] || ! is_domain "$domain" && return 1
    else
        while true; do
            read -rp "Please enter your domain name: " domain
            domain="${domain// /}"
            [[ -z "$domain" ]] && continue
            is_domain "$domain" && break
            echo -e "${red}Invalid domain format${plain}"
        done
    fi

    SSL_ISSUED_DOMAIN="${domain}"
    local certPath="/root/cert/${domain}"
    mkdir -p "$certPath"

    local WebPort=80
    prompt_or_default WebPort "Please choose which port to use (default is 80): " "80" XUI_ACME_HTTP_PORT

    systemctl stop x-ui 2>/dev/null || rc-service x-ui stop 2>/dev/null

    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force
    [[ -n "${XUI_ACME_EMAIL:-}" ]] && ~/.acme.sh/acme.sh --register-account -m "${XUI_ACME_EMAIL}" >/dev/null 2>&1
    ~/.acme.sh/acme.sh --issue -d ${domain} $(acme_listen_flag) --standalone --httpport ${WebPort} --force

    if [ $? -ne 0 ]; then
        systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null
        return 1
    fi

    local reloadCmd="systemctl restart x-ui || rc-service x-ui restart"
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem \
        --reloadcmd "${reloadCmd}" 2>&1

    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    chmod 600 $certPath/privkey.pem 2>/dev/null
    chmod 644 $certPath/fullchain.pem 2>/dev/null

    systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null

    if [[ -f "/root/cert/${domain}/privkey.pem" && -f "/root/cert/${domain}/fullchain.pem" ]]; then
        ${xui_folder}/x-ui cert -webCert "/root/cert/${domain}/fullchain.pem" \
            -webCertKey "/root/cert/${domain}/privkey.pem"
        systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null
    fi
    return 0
}

prompt_and_setup_ssl() {
    local panel_port="$1"
    local web_base_path="$2"
    local server_ip="$3"

    local ssl_choice=""
    SSL_SCHEME="https"

    echo -e "${yellow}Choose SSL certificate setup method:${plain}"
    echo -e "${green}1.${plain} Let's Encrypt for Domain"
    echo -e "${green}2.${plain} Let's Encrypt for IP Address"
    echo -e "${green}3.${plain} Custom SSL Certificate"
    echo -e "${green}4.${plain} Skip SSL"

    if [[ "$NONINTERACTIVE" == "1" ]]; then
        case "${XUI_SSL_MODE:-none}" in
            domain) ssl_choice="1" ;;
            ip) ssl_choice="2" ;;
            *) ssl_choice="4" ;;
        esac
    else
        read -rp "Choose an option (default 2 for IP): " ssl_choice
        ssl_choice="${ssl_choice// /}"
        [[ "$ssl_choice" != "1" && "$ssl_choice" != "3" && "$ssl_choice" != "4" ]] && ssl_choice="2"
    fi

    case "$ssl_choice" in
        1)
            if ssl_cert_issue; then
                SSL_HOST="${SSL_ISSUED_DOMAIN:-$server_ip}"
            else
                SSL_HOST="$server_ip"
            fi
            ;;
        2)
            local ipv6_addr=""
            prompt_or_default ipv6_addr "IPv6 address (leave empty to skip): " "" XUI_SSL_IPV6
            systemctl stop x-ui >/dev/null 2>&1
            if setup_ip_certificate "${server_ip}" "${ipv6_addr}"; then
                SSL_HOST="${server_ip}"
            else
                SSL_HOST="${server_ip}"
            fi
            ;;
        3)
            local custom_cert="" custom_key="" custom_domain=""
            read -rp "Domain for certificate: " custom_domain
            while true; do
                read -rp "Certificate path: " custom_cert
                custom_cert=$(echo "$custom_cert" | tr -d '"' | tr -d "'")
                [[ -f "$custom_cert" && -r "$custom_cert" && -s "$custom_cert" ]] && break
                echo -e "${red}File not found or empty${plain}"
            done
            while true; do
                read -rp "Private key path: " custom_key
                custom_key=$(echo "$custom_key" | tr -d '"' | tr -d "'")
                [[ -f "$custom_key" && -r "$custom_key" && -s "$custom_key" ]] && break
                echo -e "${red}File not found or empty${plain}"
            done
            ${xui_folder}/x-ui cert -webCert "$custom_cert" -webCertKey "$custom_key" >/dev/null 2>&1
            SSL_HOST="${custom_domain:-$server_ip}"
            systemctl restart x-ui >/dev/null 2>&1
            ;;
        4)
            SSL_SCHEME="http"
            SSL_HOST="${server_ip}"
            systemctl restart x-ui >/dev/null 2>&1
            ;;
    esac
}

config_after_install() {
    local existing_hasDefaultCredential=$(${xui_folder}/x-ui setting -show true | grep -Eo 'hasDefaultCredential: .+' | awk '{print $2}')
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    local existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')

    local URL_lists=(
        "https://api4.ipify.org"
        "https://ipv4.icanhazip.com"
        "https://v4.api.ipinfo.io/ip"
        "https://ipv4.myexternalip.com/raw"
        "https://4.ident.me"
    )
    local server_ip=""
    for ip_address in "${URL_lists[@]}"; do
        local response=$(curl -s -w "\n%{http_code}" --max-time 3 "${ip_address}" 2>/dev/null)
        local http_code=$(echo "$response" | tail -n1)
        local ip_result=$(echo "$response" | head -n-1 | tr -d '[:space:]"')
        if [[ "${http_code}" == "200" && "${ip_result}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            server_ip="${ip_result}"
            break
        fi
    done

    [[ -z "$server_ip" ]] && server_ip="${XUI_SERVER_IP:-}"

    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_webBasePath="${XUI_WEB_BASE_PATH:-$(gen_random_string 18)}"
            local config_username="${XUI_USERNAME:-$(gen_random_string 10)}"
            local config_password="${XUI_PASSWORD:-$(gen_random_string 10)}"
            local config_port=""

            if [[ "$NONINTERACTIVE" == "1" ]]; then
                config_port="${XUI_PANEL_PORT:-$(shuf -i 1024-62000 -n 1)}"
            else
                read -rp "Customize Panel Port? [y/n]: " config_confirm
                if [[ "${config_confirm}" == "y" || "${config_confirm}" == "Y" ]]; then
                    read -rp "Please set up the panel port: " config_port
                else
                    config_port=$(shuf -i 1024-62000 -n 1)
                fi
            fi

            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}" \
                -port "${config_port}" -webBasePath "${config_webBasePath}"

            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     SSL Certificate Setup                 ${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"

            prompt_and_setup_ssl "${config_port}" "${config_webBasePath}" "${server_ip}"

            local config_apiToken=$(${xui_folder}/x-ui setting -getApiToken true | grep -Eo 'apiToken: .+' | awk '{print $2}')

            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     Panel Installation Complete!          ${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}Username:    ${config_username}${plain}"
            echo -e "${green}Password:    ${config_password}${plain}"
            echo -e "${green}Port:        ${config_port}${plain}"
            echo -e "${green}WebBasePath: ${config_webBasePath}${plain}"
            echo -e "${green}Access URL:  ${SSL_SCHEME}://${SSL_HOST}:${config_port}/${config_webBasePath}${plain}"
            echo -e "${green}API Token:   ${config_apiToken}${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}⚠ IMPORTANT: Save these credentials securely!${plain}"

            # ───── راه‌اندازی سیستم ادمین ─────
            echo ""
            echo -e "${cyan}═══════════════════════════════════════════${plain}"
            echo -e "${cyan}     راه‌اندازی سیستم مدیریت ادمین       ${plain}"
            echo -e "${cyan}═══════════════════════════════════════════${plain}"
            init_admin_system

            if [[ "$NONINTERACTIVE" != "1" ]]; then
                read -rp "آیا می‌خواید یک ادمین فرعی اضافه کنید? [y/n]: " add_sub_admin
                if [[ "$add_sub_admin" == "y" || "$add_sub_admin" == "Y" ]]; then
                    add_admin
                fi
            fi

            : "${SSL_SCHEME:=https}"
            : "${SSL_HOST:=${server_ip}}"
            write_install_result "${config_username}" "${config_password}" "${config_port}" \
                "${config_webBasePath}" "${SSL_SCHEME}" "${SSL_HOST}" "${config_apiToken}" "sqlite"
        else
            local config_webBasePath=$(gen_random_string 18)
            ${xui_folder}/x-ui setting -webBasePath "${config_webBasePath}"
            if [[ -z "${existing_cert}" ]]; then
                prompt_and_setup_ssl "${existing_port}" "${config_webBasePath}" "${server_ip}"
            fi
            echo -e "${green}Access URL: ${SSL_SCHEME:-https}://${SSL_HOST:-$server_ip}:${existing_port}/${config_webBasePath}${plain}"
        fi
    else
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_username="${XUI_USERNAME:-$(gen_random_string 10)}"
            local config_password="${XUI_PASSWORD:-$(gen_random_string 10)}"
            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}"
            echo -e "${green}Username: ${config_username}${plain}"
            echo -e "${green}Password: ${config_password}${plain}"
        fi
        existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
        if [[ -z "$existing_cert" ]]; then
            prompt_and_setup_ssl "${existing_port}" "${existing_webBasePath}" "${server_ip}"
        fi
    fi

    ${xui_folder}/x-ui migrate
}

setup_fail2ban() {
    [[ -n "${XUI_ENABLE_FAIL2BAN+x}" && "${XUI_ENABLE_FAIL2BAN}" != "true" ]] && return 0
    [[ ! -x /usr/bin/x-ui ]] && return 0
    echo -e "${green}Setting up Fail2ban...${plain}"
    /usr/bin/x-ui setup-fail2ban || true
    return 0
}

install_x-ui() {
    cd ${xui_folder%/x-ui}/

    if [ $# == 0 ]; then
        tag_version=$(curl -Ls --retry 5 --retry-delay 3 --connect-timeout 15 --max-time 60 \
            "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" \
            | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        [[ -z "$tag_version" ]] && echo -e "${red}Failed to fetch version${plain}" && exit 1
        echo -e "Got x-ui latest version: ${tag_version}"
        curl -fLR --retry 5 --retry-delay 3 --connect-timeout 15 --max-time 300 \
            -o ${xui_folder}-linux-$(arch).tar.gz \
            https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        [[ $? -ne 0 ]] && echo -e "${red}Downloading x-ui failed${plain}" && exit 1
    else
        tag_version=$1
        if [[ "$tag_version" == "dev" || "$tag_version" == "dev-latest" ]]; then
            tag_version="dev-latest"
        else
            tag_version_numeric=${tag_version#v}
            min_version="2.3.5"
            if [[ "$(printf '%s\n' "$min_version" "$tag_version_numeric" | sort -V | head -n1)" != "$min_version" ]]; then
                echo -e "${red}Please use version >= v2.3.5${plain}" && exit 1
            fi
        fi
        curl -fLR --retry 5 --retry-delay 3 --connect-timeout 15 --max-time 300 \
            -o ${xui_folder}-linux-$(arch).tar.gz \
            https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        [[ $? -ne 0 ]] && echo -e "${red}Download failed${plain}" && exit 1
    fi

    curl -fLRo /usr/bin/x-ui-temp https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh
    [[ $? -ne 0 ]] && echo -e "${red}Failed to download x-ui.sh${plain}" && exit 1

    if [[ -e ${xui_folder}/ ]]; then
        [[ $release == "alpine" ]] && rc-service x-ui stop || systemctl stop x-ui
        pkill -f 'mtg-linux-[^ ]* run ' >/dev/null 2>&1 || true
        rm ${xui_folder}/ -rf
    fi

    tar zxvf x-ui-linux-$(arch).tar.gz
    rm x-ui-linux-$(arch).tar.gz -f

    cd x-ui
    chmod +x x-ui x-ui.sh

    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
        [[ -f bin/mtg-linux-$(arch) ]] && mv bin/mtg-linux-$(arch) bin/mtg-linux-arm && chmod +x bin/mtg-linux-arm
    fi
    chmod +x x-ui bin/xray-linux-$(arch)
    [[ -f bin/mtg-linux-arm ]] && chmod +x bin/mtg-linux-arm
    [[ -f bin/mtg-linux-$(arch) ]] && chmod +x bin/mtg-linux-$(arch)

    mv -f /usr/bin/x-ui-temp /usr/bin/x-ui
    chmod +x /usr/bin/x-ui
    mkdir -p /var/log/x-ui
    config_after_install

    if [ -d "/etc/.git" ]; then
        if [ -f "/etc/.gitignore" ]; then
            grep -q "x-ui/x-ui.db" "/etc/.gitignore" || echo "x-ui/x-ui.db" >> "/etc/.gitignore"
        else
            echo "x-ui/x-ui.db" > "/etc/.gitignore"
        fi
    fi

    if [[ $release == "alpine" ]]; then
        curl -fLRo /etc/init.d/x-ui https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.rc
        [[ $? -ne 0 ]] && exit 1
        chmod +x /etc/init.d/x-ui
        rc-update add x-ui
        rc-service x-ui start
    else
        local service_installed=false

        for svc_file in "x-ui.service" "x-ui.service.debian" "x-ui.service.arch" "x-ui.service.rhel"; do
            if [ -f "$svc_file" ]; then
                cp -f "$svc_file" ${xui_service}/x-ui.service >/dev/null 2>&1 && service_installed=true && break
            fi
        done

        if [ "$service_installed" = false ]; then
            case "${release}" in
                ubuntu | debian | armbian)
                    curl -fLRo ${xui_service}/x-ui.service \
                        https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.debian >/dev/null 2>&1 ;;
                arch | manjaro | parch)
                    curl -fLRo ${xui_service}/x-ui.service \
                        https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.arch >/dev/null 2>&1 ;;
                *)
                    curl -fLRo ${xui_service}/x-ui.service \
                        https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.rhel >/dev/null 2>&1 ;;
            esac
            [[ $? -ne 0 ]] && exit 1
            service_installed=true
        fi

        if [ "$service_installed" = true ]; then
            chown root:root ${xui_service}/x-ui.service >/dev/null 2>&1
            chmod 644 ${xui_service}/x-ui.service >/dev/null 2>&1
            systemctl daemon-reload
            systemctl enable x-ui
            systemctl start x-ui
        else
            exit 1
        fi
    fi

    setup_fail2ban

    echo -e "${green}x-ui ${tag_version} installation finished!${plain}"
    echo ""
    echo -e "┌───────────────────────────────────────────────────────┐
│  ${blue}x-ui control menu usages (subcommands):${plain}              │
│                                                       │
│  ${blue}x-ui${plain}              - Admin Management Script          │
│  ${blue}x-ui start${plain}        - Start                            │
│  ${blue}x-ui stop${plain}         - Stop                             │
│  ${blue}x-ui restart${plain}      - Restart                          │
│  ${blue}x-ui status${plain}       - Current Status                   │
│  ${blue}x-ui settings${plain}     - Current Settings                 │
│  ${blue}x-ui enable${plain}       - Enable Autostart on OS Startup   │
│  ${blue}x-ui disable${plain}      - Disable Autostart on OS Startup  │
│  ${blue}x-ui log${plain}          - Check logs                       │
│  ${blue}x-ui banlog${plain}       - Check Fail2ban ban logs          │
│  ${blue}x-ui update${plain}       - Update                           │
│  ${blue}x-ui legacy${plain}       - Legacy version                   │
│  ${blue}x-ui install${plain}      - Install                          │
│  ${blue}x-ui uninstall${plain}    - Uninstall                        │
│                                                       │
│  ${cyan}قابلیت‌های جدید:${plain}                                  │
│  ${cyan}x-ui sni${plain}          - SNI Scanner                      │
│  ${cyan}x-ui admins${plain}       - مدیریت ادمین‌ها                │
│  ${cyan}x-ui inbound${plain}      - ساخت Inbound با SNI             │
└───────────────────────────────────────────────────────┘"

    # نصب shortcut های جدید در x-ui cli
    install_extended_cli_hooks
}

# اضافه کردن دستورات جدید به x-ui CLI
install_extended_cli_hooks() {
    local xui_cli="/usr/bin/x-ui"
    local ext_script="/usr/local/x-ui/x-ui-extended.sh"

    # کپی این اسکریپت
    cp -f "$0" "$ext_script" 2>/dev/null || true
    chmod +x "$ext_script" 2>/dev/null || true

    # بررسی اینکه آیا hook قبلاً اضافه شده
    if ! grep -q "x-ui-extended" "$xui_cli" 2>/dev/null; then
        cat >> "$xui_cli" << 'HOOK_EOF'

# Extended commands (SNI Scanner + Admin Management)
case "$1" in
    sni)
        source /usr/local/x-ui/x-ui-extended.sh 2>/dev/null
        run_sni_scanner
        ;;
    admins)
        source /usr/local/x-ui/x-ui-extended.sh 2>/dev/null
        manage_admins_menu
        ;;
    inbound)
        source /usr/local/x-ui/x-ui-extended.sh 2>/dev/null
        build_inbound_with_sni
        ;;
esac
HOOK_EOF
        echo -e "${green}دستورات جدید به x-ui CLI اضافه شد${plain}"
    fi
}

# ============================================================
# نقطه شروع
# ============================================================

# اگر مستقیم اجرا شود (نه source)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then
        # بدون آرگومان: نمایش منوی امکانات جدید
        show_extended_menu
    elif [[ "$1" == "install" ]]; then
        echo -e "${green}Running full installation...${plain}"
        install_base
        install_x-ui "${2:-}"
    elif [[ "$1" == "sni" ]]; then
        run_sni_scanner
    elif [[ "$1" == "admins" ]]; then
        manage_admins_menu
    elif [[ "$1" == "inbound" ]]; then
        build_inbound_with_sni
    else
        # نصب با نسخه مشخص
        echo -e "${green}Running...${plain}"
        install_base
        install_x-ui "$1"
    fi
fi

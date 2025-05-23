#!/bin/bash
set -eo pipefail

# 彩色输出定义
color_red='\033[1;31m'
color_green='\033[1;32m'
color_yellow='\033[1;33m'
color_blue='\033[1;34m'
color_reset='\033[0m'

# 全局日志函数
log_info()    { echo -e "${color_blue}[INFO] $(date +'%Y-%m-%d %T') $*${color_reset}" | tee -a "$LOG_FILE"; }
log_warning() { echo -e "${color_yellow}[WARN] $(date +'%Y-%m-%d %T') $*${color_reset}" | tee -a "$LOG_FILE"; }
log_error()   { echo -e "${color_red}[ERROR] $(date +'%Y-%m-%d %T') $*${color_reset}" | tee -a "$LOG_FILE"; exit 1; }

# 默认日志文件
: ${LOG_FILE:=minio_upload.log}

# 加载环境变量
if [ -f .env ]; then
    log_info "加载 .env 文件中的环境变量..."
    # 使用更安全的方式加载环境变量
    while IFS= read -r line || [[ -n "$line" ]]; do
        # 跳过注释和空行
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        # 导出环境变量
        export "$line"
    done < .env
fi

# 配置信息（从环境变量获取）
: ${MINIO_URL:?"必须设置MINIO_URL环境变量"}
: ${MINIO_ACCESS_KEY:?"必须设置MINIO_ACCESS_KEY环境变量"}
: ${MINIO_SECRET_KEY:?"必须设置MINIO_SECRET_KEY环境变量"}
: ${MINIO_BUCKET:?"必须设置MINIO_BUCKET环境变量"}
: ${R2_URL:?"必须设置R2_URL环境变量"}
: ${R2_ACCESS_KEY:?"必须设置R2_ACCESS_KEY环境变量"}
: ${R2_SECRET_KEY:?"必须设置R2_SECRET_KEY环境变量"}
: ${R2_BUCKET:?"必须设置R2_BUCKET环境变量"}
: ${UPLOAD_DIR:=$(date +%Y%m%d)}
: ${MAX_RETRIES:=3}
: ${TIMEOUT:=300}
: ${SHA_FILE:=SHA256SUMS}

# ---------- 签名生成函数 ----------
generate_v2_signature() {
    local secret_key="$1"
    local http_request="$2"
    echo -en "$http_request" | openssl sha1 -binary -hmac "$secret_key" | base64 || log_error "生成V2签名失败"
}

generate_v4_signature() {
    local secret_key="$1"
    local access_key="$2"
    local date_scope="$3"
    local region="$4"
    local service="$5"
    local canonical_request="$6"
    
    local hashed_canonical=$(echo -en "$canonical_request" | openssl dgst -sha256 | awk '{print $2}')
    local string_to_sign="AWS4-HMAC-SHA256\n${date_scope}T000000Z\n${date_scope}/${region}/${service}/aws4_request\n${hashed_canonical}"
    
    # 生成签名密钥
    local kSecret=$(echo -en "AWS4${secret_key}" | iconv -t utf-8)
    local kDate=$(echo -n "$date_scope" | openssl dgst -sha256 -mac HMAC -macopt "key:${kSecret}" | awk '{print $2}')
    local kRegion=$(echo -n "$region" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${kDate}" | awk '{print $2}')
    local kService=$(echo -n "$service" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${kRegion}" | awk '{print $2}')
    local kSigning=$(echo -n "aws4_request" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${kService}" | awk '{print $2}')
    echo -en "$string_to_sign" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${kSigning}" | awk '{print $2}'
}

# ---------- SSH密钥管理 ----------
setup_ssh_keys() {
    log_info "======== 生成SSH密钥对 ========"
    {
        set -x
        # 清理旧密钥
        rm -f ssh_key ssh_key.pub
        
        # 生成新密钥
        ssh-keygen -t rsa -f ssh_key -N '' -q
        
        # 写入authorized_keys
        cat ssh_key.pub > http/authorized_keys
        
        set +x
    } |& tee -a "$LOG_FILE"
}

# ---------- Cloud-Init模板管理 ----------
setup_cloud_init_template() {
    log_info "======== 初始化Cloud-Init模板 ========"
    {
        set -x
        
        # 处理user-data模板，只考虑两种情况：有模板或没有模板
        if [[ ! -f "http/user-data.template" ]]; then
            # 如果没有模板文件，创建一个基本模板
            log_info "未找到模板文件，创建基本模板"
            cat > http/user-data.template << EOF
#cloud-config
ssh_pwauth: false
disable_root: false

users:
  - name: builder
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ssh-key-placeholder

version: 2
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: no
      addresses: [ip-placeholder/24]
      routes:
        - to: default
          via: gateway-placeholder
      nameservers:
        addresses: [dns-placeholder]
EOF
            log_info "已创建基本模板文件：http/user-data.template"
        else
            # 如果已有模板文件，确保包含必要的占位符
            log_info "使用现有user-data.template模板"
            
            # 确保包含SSH密钥占位符
            if ! grep -q "ssh-key-placeholder" http/user-data.template; then
                log_warning "现有模板中不包含SSH密钥占位符，请确保模板中包含 'ssh-key-placeholder'"
            fi
            
            # 确保IP配置正确
            if grep -q "dhcp4: yes" http/user-data.template; then
                # 将dhcp4改为静态IP配置
                log_warning "现有模板使用DHCP，修改为静态IP配置"
                sed -i 's/dhcp4: yes/dhcp4: no/' http/user-data.template
                # 添加IP地址配置
                if ! grep -q "addresses:" http/user-data.template || ! grep -q "ip-placeholder" http/user-data.template; then
                    sed -i '/dhcp4: no/a\      addresses: [ip-placeholder/24]' http/user-data.template
                fi
            elif ! grep -q "ip-placeholder" http/user-data.template; then
                # 确保有IP地址占位符
                log_warning "现有模板中不包含IP地址占位符，添加IP配置"
                if grep -q "addresses:" http/user-data.template; then
                    # 更新现有IP配置
                    sed -i '/addresses:/s/\[[^]]*\]/[ip-placeholder\/24]/' http/user-data.template
                else
                    # 添加IP配置占位符
                    sed -i '/dhcp4: no/a\      addresses: [ip-placeholder/24]' http/user-data.template
                fi
            fi
            
            # 确保包含DNS占位符
            if ! grep -q "dns-placeholder" http/user-data.template; then
                log_warning "现有模板中不包含DNS占位符，添加DNS配置"
                if grep -q "nameservers:" http/user-data.template; then
                    # 更新现有DNS配置
                    sed -i "/nameservers:/,+1 s/addresses:.*/addresses: [dns-placeholder]/g" http/user-data.template
                else
                    # 添加DNS配置占位符
                    sed -i '/addresses: \[ip-placeholder\/24\]/a\      nameservers:\n        addresses: [dns-placeholder]' http/user-data.template
                fi
            fi
            
            # 处理网关配置：将gateway/gateway4转换为routes格式
            if grep -q "gateway:" http/user-data.template || grep -q "gateway4:" http/user-data.template; then
                log_warning "现有模板使用过时的gateway/gateway4配置，替换为routes配置"
                # 删除旧的gateway或gateway4行
                sed -i '/gateway4:/d' http/user-data.template
                sed -i '/gateway:/d' http/user-data.template
                # 添加routes配置
                if ! grep -q "routes:" http/user-data.template; then
                    sed -i '/addresses: \[ip-placeholder\/24\]/a\      routes:\n        - to: default\n          via: gateway-placeholder' http/user-data.template
                fi
            elif ! grep -q "routes:" http/user-data.template; then
                log_warning "现有模板中不包含routes配置，添加routes配置"
                sed -i '/addresses: \[ip-placeholder\/24\]/a\      routes:\n        - to: default\n          via: gateway-placeholder' http/user-data.template
            elif ! grep -q "gateway-placeholder" http/user-data.template; then
                log_warning "routes配置中不包含网关占位符，添加网关占位符"
                sed -i '/via:/s/via:.*/via: gateway-placeholder/' http/user-data.template
            fi
            
            # 设置renderer为networkd
            if ! grep -q "renderer: networkd" http/user-data.template; then
                log_warning "现有模板未指定renderer为networkd，更新配置"
                if grep -q "renderer:" http/user-data.template; then
                    sed -i 's/renderer:.*/renderer: networkd/' http/user-data.template
                else
                    sed -i '/network:/a\  renderer: networkd' http/user-data.template
                fi
            fi
        fi
        
        set +x
    } |& tee -a "$LOG_FILE"
}

# ---------- 根据cn_flag配置cloudinit IP ----------
configure_cloud_init() {
    local cn_flag="$1"
    
    log_info "配置cloudinit和SSH （cn_flag=${cn_flag}）..."
    cp http/user-data.template http/user-data
    
    # 替换SSH密钥占位符
    sed -i "s|ssh-key-placeholder|$(cat ssh_key.pub)|g" http/user-data
    
    # 配置IP地址
    local ip_address
    if [ "$cn_flag" = "true" ]; then
        ip_address="10.114.51.134"
    else
        ip_address="10.114.51.133"
    fi
    log_info "设置IP地址: ${ip_address}"
    sed -i "s|ip-placeholder|${ip_address}|g" http/user-data
    
    # 配置网关
    log_info "设置网关: 10.114.51.4"
    sed -i "s|gateway-placeholder|10.114.51.4|g" http/user-data
    
    # 配置DNS
    if [ "$cn_flag" = "true" ]; then
        # 使用境内DNS
        log_info "设置境内DNS: 223.5.5.5"
        sed -i "s|dns-placeholder|223.5.5.5|g" http/user-data
    else
        # 使用默认DNS
        log_info "设置默认DNS: 1.1.1.1"
        sed -i "s|dns-placeholder|1.1.1.1|g" http/user-data
    fi
}

# ---------- 构建镜像部分 ----------
build_images() {
    # 清理旧构建文件
    log_info "清理旧构建文件..."
    rm -rf output-*

    # 定义构建系统列表
    systems=(
        "almalinux 8"
        "almalinux 9"
        "rocky 8"
        "rocky 9"
        "ubuntu 20"
        "ubuntu 22"
        "ubuntu 24"
        "debian 11"
        "debian 12"
    )

    # 构建函数
    build_image() {
        local os="$1"
        local version="$2"
        local hcl_file="${os}/${version}.pkr.hcl"
        
        log_info "========================================"
        log_info "开始构建 ${color_green}${os} ${version}${color_reset}"
        log_info "========================================"
        
        # 带重试构建函数
        build_with_retry() {
            local build_cmd="$1"
            local attempt=1
            local result=0
            
            while [ $attempt -le $MAX_RETRIES ]; do
                log_info "尝试构建 (第 $attempt/$MAX_RETRIES 次)"
                eval "$build_cmd" && result=0 || result=1
                if [ $result -eq 0 ]; then
                    return 0
                else
                    log_warning "构建失败，将在 5 秒后重试..."
                    sleep 5
                    ((attempt++))
                fi
            done
            return 1
        }

        # 带CN标志的构建
        log_info "执行大陆镜像构建: ${hcl_file}"
        configure_cloud_init "true"
        build_with_retry "sudo -E packer build -var 'cn_flag=true' $hcl_file" || log_error "构建失败: ${hcl_file} (CN模式) 超过最大重试次数"
        
        # 标准构建
        log_info "执行标准构建: ${hcl_file}"
        configure_cloud_init "false"
        build_with_retry "sudo -E packer build $hcl_file" || log_error "构建失败: ${hcl_file} 超过最大重试次数"
    }

    # 遍历构建
    for entry in "${systems[@]}"; do
        IFS=' ' read -ra parts <<< "$entry"
        os="${parts[0]}"
        version="${parts[1]}"
        build_image "$os" "$version"
    done
}

# ---------- 上传部分 ----------
upload_images() {
    # 依赖检查
    check_dependencies() {
        local deps=("curl" "openssl" "file" "basename" "du" "stat")
        for cmd in "${deps[@]}"; do
            if ! command -v "$cmd" &> /dev/null; then
                echo -e "${color_red}缺少必要依赖: $cmd${color_reset}"
                exit 1
            fi
        done
    }

    # 上传到指定服务
    upload_to_service() {
        local service_url="$1"
        local access_key="$2"
        local secret_key="$3"
        local bucket_name="$4"
        local file_path="$5"
        local is_version_file="${6:-false}"
        
        local file_name=$(basename "$file_path")
        local file_size=$(stat -c%s "$file_path")
        local content_sha=$(sha256sum "$file_path" | awk '{print $1}')
        local content_type=$(file -b --mime-type "$file_path")
        local request_path="/${bucket_name}/${UPLOAD_DIR}/${file_name}"
        
        if [ "$is_version_file" = true ]; then
            request_path="/${bucket_name}/latest_version.txt"
        fi

        if [[ $service_url == *"cloudflarestorage.com"* ]]; then
            # R2使用V4签名
            local amz_date=$(date -u +"%Y%m%dT%H%M%SZ")
            local date_scope=$(date -u +"%Y%m%d")
            local region="auto"
            local service="s3"
            
            local canonical_request="PUT\n${request_path}\n\nhost:$(echo $service_url | awk -F/ '{print $3}')\nx-amz-content-sha256:${content_sha}\nx-amz-date:${amz_date}\n\nhost;x-amz-content-sha256;x-amz-date\n${content_sha}"
            local signature=$(generate_v4_signature "$secret_key" "$access_key" "$date_scope" "$region" "$service" "$canonical_request")

            log_info "上传到 R2 (V4签名): ${file_name}"
            
            curl -fS --connect-timeout 20 --retry 2 \
                -X PUT \
                -H "Host: $(echo $service_url | awk -F/ '{print $3}')" \
                -H "x-amz-content-sha256: ${content_sha}" \
                -H "x-amz-date: ${amz_date}" \
                -H "Authorization: AWS4-HMAC-SHA256 Credential=${access_key}/${date_scope}/${region}/${service}/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=${signature}" \
                --progress-bar \
                --upload-file "$file_path" \
                "${service_url}${request_path}" || return 1
        else
            # MinIO使用V2签名
            local http_date=$(date -u "+%a, %d %h %Y %H:%M:%S GMT")
            local http_request="PUT\n\n${content_type}\n${http_date}\n${request_path}"
            local signature=$(generate_v2_signature "$secret_key" "$http_request")

            log_info "上传到 MinIO (V2签名): ${file_name}"
            
            curl -fS --connect-timeout 20 --retry 2 \
                -X PUT \
                -H "Date: $http_date" \
                -H "Content-Type: $content_type" \
                -H "Authorization: AWS ${access_key}:${signature}" \
                --progress-bar \
                --upload-file "$file_path" \
                "${service_url}${request_path}" || return 1
        fi

        return 0
    }

    # 上传执行
    do_upload() {
        local file_path="$1"
        [[ -f "$file_path" ]] || log_error "文件不存在: $file_path"
        [[ -s "$file_path" ]] || log_error "空文件: $file_path"

        local file_name=$(basename "$file_path")
        local file_size=$(stat -c%s "$file_path")
        local content_sha=$(sha256sum "$file_path" | awk '{print $1}')

        # 上传到 MinIO
        upload_to_service "$MINIO_URL" "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY" "$MINIO_BUCKET" "$file_path" || return 1
        
        # 上传到 R2
        upload_to_service "$R2_URL" "$R2_ACCESS_KEY" "$R2_SECRET_KEY" "$R2_BUCKET" "$file_path" || return 1

        # 记录上传历史
        echo "$(date +'%FT%T'),${MINIO_BUCKET},${UPLOAD_DIR},${file_name},${file_size},${content_sha}" >> upload_history.csv
        echo "$(date +'%FT%T'),${R2_BUCKET},${UPLOAD_DIR},${file_name},${file_size},${content_sha}" >> upload_history.csv
        
        # 只记录镜像文件的SHA256，不记录校验文件本身
        if [ "$file_name" != "${SHA_FILE}" ]; then
            echo "${content_sha}  ${file_name}" >> "${SHA_FILE}"
        fi

        return 0
    }

    # 创建版本文件
    create_version_file() {
        local version_file_content=$(date +%Y%m%d)
        local temp_file=$(mktemp)
        echo "$version_file_content" > "$temp_file"
        
        # 上传到 MinIO
        upload_to_service "$MINIO_URL" "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY" "$MINIO_BUCKET" "$temp_file" true || log_warning "MinIO创建latest_version.txt失败"
        
        # 上传到 R2
        upload_to_service "$R2_URL" "$R2_ACCESS_KEY" "$R2_SECRET_KEY" "$R2_BUCKET" "$temp_file" true || log_warning "R2创建latest_version.txt失败"
        
        rm -f "$temp_file"
    }

    # 文件列表
    local files=(
        "./output-almalinux-8/almalinux-8.img"
        "./output-almalinux-8-cn/almalinux-8-cn.img"
        "./output-almalinux-9/almalinux-9.img"
        "./output-almalinux-9-cn/almalinux-9-cn.img"
        "./output-rocky-8/rocky-8.img"
        "./output-rocky-8-cn/rocky-8-cn.img"
        "./output-rocky-9/rocky-9.img"
        "./output-rocky-9-cn/rocky-9-cn.img"
        "./output-debian-12/debian-12.img"
        "./output-debian-12-cn/debian-12-cn.img"
        "./output-debian-11/debian-11.img"
        "./output-debian-11-cn/debian-11-cn.img"
        "./output-ubuntu/ubuntu-24.img"
        "./output-ubuntu-cn/ubuntu-24-cn.img"
        "./output-ubuntu-22/ubuntu-22.img"
        "./output-ubuntu-22-cn/ubuntu-22-cn.img"
        "./output-ubuntu-20/ubuntu-20.img"
        "./output-ubuntu-20-cn/ubuntu-20-cn.img"
    )

    # 开始上传流程
    check_dependencies
    log_info "======== 上传开始 ========"
    for file in "${files[@]}"; do
        local attempt=1
        while [ $attempt -le $MAX_RETRIES ]; do
            if do_upload "$file"; then
                break
            else
                log_warning "上传失败 (尝试: $attempt/$MAX_RETRIES)"
                ((attempt++))
                sleep $((attempt * 5))
            fi
        done
        [ $attempt -le $MAX_RETRIES ] || log_error "文件 ${file} 上传失败"
    done

    # 上传SHA256SUMS文件
    log_info "======== 处理校验文件 ========"
    
    # 如果校验文件存在且非空，则上传
    if [ -s "${SHA_FILE}" ]; then
        # 添加文件头到原始校验文件
        local orig_content=$(cat "${SHA_FILE}")
        {
            echo "# Generated at $(date +'%Y-%m-%d %T')"
            echo "# Cloud Images SHA256 Checksums"
            echo ""
            echo "${orig_content}"
        } > "${SHA_FILE}"
        
        # 直接上传原始校验文件
        do_upload "${SHA_FILE}"
        log_info "======== 校验文件已上传 ========"
        log_info "本地校验文件保存在: ${color_green}${SHA_FILE}${color_reset}"
    else
        log_error "校验文件为空或不存在"
    fi

    # 创建版本文件
    create_version_file
}

# ---------- 主流程 ----------
main() {
    log_info "======== 开始执行构建流程 ========"
    setup_ssh_keys
    setup_cloud_init_template
    build_images
    
    log_info "======== 创建上传目录 ========"
    log_info "目录名称: ${color_green}${UPLOAD_DIR}${color_reset}"
    
    log_info "======== 开始上传镜像 ========"
    upload_images
    log_info "======== 全部流程完成 ========"
}

main

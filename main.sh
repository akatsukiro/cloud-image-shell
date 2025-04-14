#!/bin/bash
set -eo pipefail

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
: ${LOG_FILE:=minio_upload.log}
: ${SHA_FILE:=SHA256SUMS}

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
        
        # 处理user-data模板
        if [[ ! -f "http/user-data.template" ]]; then
            if [[ -f "http/user-data" ]]; then
                log_warning "user-data模板不存在，尝试从现有user-data创建模板"
                cp http/user-data http/user-data.template
                # 将实际密钥替换为占位符
                sed -i "s|$(cat ssh_key.pub)|ssh-key-placeholder|g" http/user-data.template
                log_info "已创建模板文件：http/user-data.template"
            else
                log_error "user-data模板文件不存在且未找到现有user-data文件"
            fi
        fi
        
        log_info "生成user-data文件..."
        cp http/user-data.template http/user-data
        sed -i "s|ssh-key-placeholder|$(cat ssh_key.pub)|" http/user-data
        log_info "已更新user-data文件中的SSH公钥"
        
        set +x
    } |& tee -a "$LOG_FILE"
}

# ---------- 构建镜像部分 ----------
build_images() {
    # 清理旧构建文件
    log_info "清理旧构建文件..."
    rm -rf output-*

    # 定义构建系统列表
    systems=(
        "centos 7"
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
        build_with_retry "sudo -E packer build -var 'cn_flag=true' $hcl_file" || log_error "构建失败: ${hcl_file} (CN模式) 超过最大重试次数"
        
        # 标准构建
        log_info "执行标准构建: ${hcl_file}"
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
        "./output-centos/centos-7.img"
        "./output-centos-cn/centos-7-cn.img"
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
    build_images
    
    log_info "======== 创建上传目录 ========"
    log_info "目录名称: ${color_green}${UPLOAD_DIR}${color_reset}"
    
    log_info "======== 开始上传镜像 ========"
    upload_images
    log_info "======== 全部流程完成 ========"
}

main

# 检查参数是否提供正确
if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

rsync -av --exclude='backend/data' backend build webui:/mnt/yyy/webui/version/$1

ssh webui "ln -snf /mnt/yyy/webui/version/$1 /mnt/xxx/webui/current"

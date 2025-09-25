#!/bin/bash
# 服务监控脚本

while true; do
    # 检查PM2服务状态
    if ! pm2 list | grep -q "lengthwords-api.*online"; then
        echo "$(date): 服务异常，正在重启..."
        pm2 restart lengthwords-api
    fi
    
    # 检查API是否响应
    if ! curl -k -s https://lengthwords.top:8443/api/test > /dev/null; then
        echo "$(date): API无响应，正在重启..."
        pm2 restart lengthwords-api
    fi
    
    # 每5分钟检查一次
    sleep 300
done

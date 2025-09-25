#!/bin/bash
echo "清理临时文件..."
rm -f /opt/lengthwords/*.backup
rm -f /opt/lengthwords/*.tmp
rm -f /opt/lengthwords/logs/*.log
echo "清理完成"

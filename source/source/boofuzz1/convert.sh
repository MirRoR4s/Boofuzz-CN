#!/bin/bash

# 遍历当前目录下的所有目录
for dir in */; do

  # 进入目录
  cd "$dir"

  # 检查是否存在 readme.md 文件
  if [ -f "readme.md" ]; then

    # 获取目录名称
    directory=$(basename "$(pwd)")

    # 使用 pandoc 将 readme.md 转换为 rst 格式并保存为相应的文件
    pandoc -s readme.md -o "${directory}.rst"

    echo "已将 ${directory}/readme.md 转换为 ${directory}.rst"
  fi

  # 返回上级目录
  cd ..
done

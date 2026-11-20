# package.ps1 — 把 displus(DIS 全解)打包成可分发的 zip
# Copyright (C) 2026 zhenming(振茗)
# SPDX-License-Identifier: GPL-2.0-or-later
# 用法: powershell -File tools\package.ps1 [版本号]
# 效果: 在仓库根目录生成 displus-<版本>.zip,内含分发给别人所需的全部文件:
#   displus.lua        入口
#   modules\           模块目录(全部 .luamod,入口 dofile 加载)
#   README.md          安装/使用说明
#   LICENSE            GPL-2.0-or-later 许可证全文(分发必须附带)
#   tools\deploy.ps1   一键部署脚本
#   samples\           样例抓包(all_pdus.pcap)
# 不含 .git / .vscode / .gitignore 等开发文件

$ErrorActionPreference = "Stop"

$repo     = Split-Path -Parent $PSScriptRoot
$version  = if ($args.Count -ge 1) { $args[0] } else { "1.0.0" }
$zipName  = "displus-$version.zip"
$zipPath  = Join-Path $repo $zipName
$modCount = (Get-ChildItem (Join-Path $repo "modules") -Recurse -File).Count

# 1) 建临时目录,按目标结构摆放要发的文件
$stage = Join-Path $env:TEMP ("displus_pkg_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path (Join-Path $stage "tools") -Force | Out-Null

Copy-Item (Join-Path $repo "displus.lua")       $stage
Copy-Item (Join-Path $repo "modules")           (Join-Path $stage "modules") -Recurse
Copy-Item (Join-Path $repo "README.md")         $stage
Copy-Item (Join-Path $repo "LICENSE")           $stage
Copy-Item (Join-Path $repo "tools\deploy.ps1")  (Join-Path $stage "tools\deploy.ps1")
Copy-Item (Join-Path $repo "samples")           (Join-Path $stage "samples") -Recurse

# 2) 打成 zip(覆盖同名旧文件)
# 注意:必须传完整路径字符串,传 Get-ChildItem 对象在 PowerShell 5.1 会按文件名
# 相对当前目录解析,可能误打包仓库本体的同名目录
$items = Get-ChildItem $stage | ForEach-Object { $_.FullName }
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $items -DestinationPath $zipPath

# 3) 清理临时目录
Remove-Item $stage -Recurse -Force

Write-Host "已生成 $zipName ($((Get-Item $zipPath).Length) 字节)"
Write-Host "内含:displus.lua、modules\($modCount 个 .luamod)、README.md、LICENSE、tools\deploy.ps1、samples\all_pdus.pcap"

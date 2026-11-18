# deploy.ps1 — 将 displus(DIS 全解)插件部署到 Wireshark 个人插件目录
# Copyright (C) 2026 zhenming(振茗)
# SPDX-License-Identifier: GPL-2.0-or-later
# 用法: powershell -File tools\deploy.ps1
# 效果:
#   %APPDATA%\Wireshark\plugins\displus.lua         (入口,覆盖)
#   %APPDATA%\Wireshark\plugins\displus_mod\*.luamod (模块目录,先清后拷)
# 部署后 Wireshark 内 Ctrl+Shift+L 重载,或重启 Wireshark

$ErrorActionPreference = "Stop"

$repo    = Split-Path -Parent $PSScriptRoot
$plugins = Join-Path $env:APPDATA "Wireshark\plugins"
$dstMod  = Join-Path $plugins "displus_mod"

if (-not (Test-Path $plugins)) {
    New-Item -ItemType Directory -Path $plugins | Out-Null
}

# 2) 入口
Copy-Item (Join-Path $repo "displus.lua") $plugins -Force
Write-Host "已部署入口 displus.lua"

# 3) 模块目录(.luamod 不会被 Wireshark 自动加载,由入口 dofile)
if (Test-Path $dstMod) { Remove-Item $dstMod -Recurse -Force }
Copy-Item (Join-Path $repo "modules") $dstMod -Recurse -Force
Write-Host "已部署模块目录 displus_mod\ ($((Get-ChildItem $dstMod -Recurse -File).Count) 个文件)"

Write-Host ""
Write-Host "完成。Wireshark 中按 Ctrl+Shift+L 重载 Lua 插件(或重启)。"
Write-Host "提醒:若曾设置 'Decode As -> DIS'(UDP 3000),请删除该绑定,否则会绕过本插件。"
---
title: Ryuk Ransomware - Is this packed?
date: 2026-05-01 23:50:00 -0600
categories: [reverse engineer, ransomware, malware, malware analysis]
tags: [blog, reverse engineer, ransomware, malware, malware analysis]
---

[Sample from MalwareBazaar](https://bazaar.abuse.ch/sample/a9643eb83d509ad4eac20a2a89d8571f8d781979ad078e89f5b75b4bcb16f65e/)

## Dynamic Analysis
```
0019FCBC  0019FD18  L"lume3\\Users\\zanez\\Desktop\\ryuk ransomware.exe"

call GetTempPathW
lea ecx, [ebp-0x28] {tempFilename}
0019FCF0  0019FCF4  L"\\Device\\HarddiskVoC:\\Users\\zanez\\AppData\\Local\\Temp\\"


0x35002606 - mw_second_stage
35002606  call    dword [GetTempFileNameW]
0019FCF0  0019FCF4  L"\\Device\\HarddiskVoC:\\Users\\zanez\\AppData\\Local\\Temp\\tmp1B36.tmp"
```

The malware spawned other two process that are the exact same process as the first binary. I dumped both processes with `ProcessExplorer`. And all the three hashes are the same:
![/assets/img/posts/ryuk_ransomware/01_hashes.png]


it then first puts this html file in the folder, thisis the first folder
![/assets/img/posts/ryuk_ransomware/02_ransom_note.png]

this seems to be the ramson note maybe_create_ryuk_page()


there is not packed second stage it just executes itself multiple times
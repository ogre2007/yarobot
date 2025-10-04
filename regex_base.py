REGEX_BASE = {
    # "packers": [(r'(WinRAR\\SFX)', -4)],
    # "repeated_chars": [(r'(?!.* ([A-Fa-f0-9])\1{8,})', -5)],
    "drives": [(r"[A-Za-z]:\\", -4)],
    "exe_extensions": [
        (
            r"(\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.pdb|\.vbs|\.tmp|\.sys|\.ps1|\.vbp|\.hta|\.lnk)",
            4,
        )
    ],
    "system_keywords": [
        (
            r"(cmd.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log)",
            5,
        )
    ],
    "protocol_keywords": [(r"(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)", 5)],
    "connection_keywords": [(r"(error|http|closed|fail|version|proxy)", 3)],
    "ua_keywords": [
        (r"(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)", 5)
    ],
    "temp_and_recycler": [(r"(TEMP|Temporary|Appdata|Recycler)", 4)],
    "malicious_keywords": [
        (
            r"(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|credentials|creds|coded|p0c|Content|host)",
            5,
        )
    ],
    "network_keywords": [
        (
            r"(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection)",
            3,
        )
    ],
    "drive": [(r"([C-Zc-z]:\\)", 4)],
    "IP": [
        (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            5,
        )
    ],
    "copyright": [(r"(coded | c0d3d |cr3w\b|Coded by |codedby)", 7)],
    "extensions_generic": [(r"\.[a-zA-Z]{3}\b", 3)],
    "all_caps": [(r"^[A-Z]{6,}$", 3)],
    "all_lower": [(r"^[a-z]{6,}$", 3)],
    "all_lower_with_space": [(r"^[a-z\s]{6,}$", 2)],
    "alll_characters": [(r"^[A-Z][a-z]{5,}$", 2)],
    "URL": [(r"(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)", 2.5)],
    "certificates": [
        (r"(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)", -4)
    ],
    "parameters": [(r"( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)", 4)],
    "directory": [(r"([a-zA-Z]:|^|%)\\[A-Za-z]{4,30}\\", 4)],
    "executable_no_dir": [(r"^[^\\]+\.(exe|com|scr|bat|sys)$", 4)],
    "date_placeholders": [(r"(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)", 3)],
    "placeholders": [(r"[^A-Za-z](%s|%d|%i|%02d|%04d|%2d|%3s)[^A-Za-z]", 3)],
    "string_parts": [
        (r"(cmd|com|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)", 3)
    ],
    "programming": [
        (
            r"(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)",
            3,
        )
    ],
    "credentials": [
        (
            r"(user|pass|login|logon|token|cookie|creds|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|identif|account|login|auth|privilege)",
            3,
        )
    ],
    "malware": [(r"(\.[a-z]/[^/]+\.txt|)", 3)],
    "variables": [(r"%[A-Z_]+%", 4)],
    "RATs": [
        (
            r"(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|metasploit|/veil|Blood)",
            5,
        )
    ],
    "paths": [(r"^[Cc]:\\\\[^PW]", 3)],
    "missed_user_profiles": [
        (
            r"[\\](users|profiles|username|benutzer|Documents and Settings|Utilisateurs|Utenti|Usuários)[\\]",
            3,
        )
    ],
    "strings_with_numbers": [(r"^[A-Z][a-z]+[0-9]+$", 1)],
    "spying": [(r"(implant)", 1)],
    "special_strings": [(r"(\\\\\.\\|kernel|.dll|usage|\\DosDevices\\)", 5)],
    "parameters": [(r"( \-[a-z] | /[a-z] | \-[a-z]:[a-zA-Z]| \/[a-z]:[a-zA-Z])", 4)],
    "file": [(r"^[a-zA-Z0-9]{3,40}\.[a-zA-Z]{3}", 3)],
    "comment": [(r"^([\*\#]+ |\[[\*\-\+]\] |[\-=]> |\[[A-Za-z]\] )", 4)],
    "typo": [(r"(!\.$|!!!$| :\)$| ;\)$|fucked|[\w]\.\.\.\.$)", 4)],
    "base64": [
        (r"^(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", 7)
    ],
    "b64exec": [
        (
            r"(TVqQAAMAAAAEAAAA//8AALgAAAA|TVpQAAIAAAAEAA8A//8AALgAAAA|TVqAAAEAAAAEABAAAAAAAAAAAAA|TVoAAAAAAAAAAAAAAAAAAAAAAAA|TVpTAQEAAAAEAAAA//8AALgAAAA)",
            5,
        )
    ],
    "malicious_intent": [
        (
            r"(loader|cmdline|ntlmhash|lmhash|infect|encrypt|exec|elevat|dump|target|victim|override|\
                            traverse|mutex|pawnde|exploited|shellcode|injected|spoofed|dllinjec|exeinj|reflective|payload|inject|back conn)",
            5,
        )
    ],
    "privilege": [
        (r"(administrator|highest|system|debug|dbg|admin|adm|root) privelege", 4)
    ],
    "system_file": [(r"(LSASS|SAM|lsass.exe|cmd.exe|LSASRV.DLL)", 4)],
    "compiler": [(r"(Release|Debug|bin|sbin)", 2)],
    "pe_exe": [(r"(\.exe|\.dll|\.sys)$", 4)],
    "string_valid": [(r"(^\\\\)", 1)],
    "malware_related": [
        (
            r"(Management Support Team1|/c rundll32|DTOPTOOLZ Co.|net start|Exec|taskkill)",
            4,
        )
    ],
    "powershell": [
        (
            r"(bypass|windowstyle | hidden |-command|IEX |Invoke-Expression|Net.Webclient|Invoke[A-Z]|\
                    Net.WebClient|-w hidden |-encoded-encodedcommand| -nop |MemoryLoadLibrary|FromBase64String|Download|EncodedCommand)",
            4,
        )
    ],
    "wmi": [(r"( /c WMIC)", 3)],
    "windows_commands": [
        (
            r"( net user | net group |ping |whoami |bitsadmin |rundll32.exe javascript:|\
                            schtasks.exe /create|/c start )",
            3,
        )
    ],
    "javascript": [
        (
            r'(new ActiveXObject\("WScript.Shell"\).Run|.Run\("cmd.exe|.Run\("%comspec%\)|.Run\("c:\\Windows|.RegisterXLL\()',
            3,
        )
    ],
    "signing_certificates": [(r"( Inc | Co.|  Ltd.,| LLC| Limited)", 2)],
    "privilege_escalation": [(r"(sysprep|cryptbase|secur32)", 2)],
    "webshells": [(r"(isset\($post\[|isset\($get\[|eval\(Request)", 2)],
    "suspicious_words": [
        (
            r"(impersonate|drop|upload|download|execute|shell|\bcmd\b|decode|rot13|decrypt)",
            2,
        )
    ],
    "suspicious_words2": [
        (
            r"([+] |[-] |[*] |injecting|exploit|dumped|dumping|scanning|scanned|elevation|\
                            elevated|payload|vulnerable|payload|reverse connect|bind shell|reverse shell| dump |\
                            back connect |privesc|privilege escalat|debug privilege| inject |interactive shell|\
                            shell commands| spawning |] target |] Transmi|] Connect|] connect|] Dump|] command |\
                            ] token|] Token |] Firing | hashes | etc/passwd| SAM | NTML|unsupported target|\
                            race condition|Token system |LoaderConfig| add user |ile upload |ile download |\
                            Attaching to |ser has been successfully added|target system |LSA Secrets|DefaultPassword|\
                            Password: |loading dll|.Execute\(|Shellcode|Loader|inject x86|inject x64|bypass|katz|\
                            spoit|ms[0-9][0-9][^0-9]|\bCVE[^a-zA-Z]|privilege::|lsadump|door)",
            4,
        )
    ],
    "mutex_pipes": [(r"(Mutex|NamedPipe|\\Global\\|\\pipe\\)", 3)],
    "usage": [(r"(isset\($post\[|isset\($get\[)", 2)],
    "hash": [(r"\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", 2)],
    "persistence": [(r"(sc.exe |schtasks|at \\\\|at [0-9]{2}:[0-9]{2})", 3)],
    "unix": [
        (
            r"(;chmod |; chmod |sh -c|/dev/tcp/|/bin/telnet|selinux| shell| cp /bin/sh )",
            3,
        )
    ],
    "attack": [
        (
            r"(attacker|brute force|bruteforce|connecting back|EXHAUSTIVE|exhaustion| spawn| evil| elevated)",
            3,
        )
    ],
    "less_value": [
        (r"(abcdefghijklmnopqsst|ABCDEFGHIJKLMNOPQRSTUVWXYZ|0123456789:;)", -5)
    ],
    "vb_backdoors": [(r"(kill|wscript|plugins|svr32|Select |)", 3)],
    "susp_strings_combo": [(r"([a-z]{4,}[!\?]|\[[!+\-]\] |[a-zA-Z]{4,}...)", 3)],
    "special_chars": [(r"(-->|!!!| <<< | >>> )", 5)],
    "swear": [(r"\b(fuck|damn|shit|penis)\b", 5)],
    "scripts": [
        (r"(%APPDATA%|%USERPROFILE%|Public|Roaming|& del|& rm| && |script)", 3)
    ],
    "uacme": [(r"(Elevation|pwnd|pawn|elevate to)", 3)],
}

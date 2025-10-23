use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
pub type RegexRules = HashMap<&'static str, Vec<(Regex, i64)>>;

lazy_static! {
    pub static ref REGEX_INSENSITIVE: RegexRules = {
        let mut m = HashMap::new();
        m.insert("drives", vec![(r"[A-Za-z]:\\", -4)]);
        m.insert(
            "exe_extensions",
            vec![(
                r"(\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.pdb|\.vbs|\.tmp|\.sys|\.ps1|\.vbp|\.hta|\.lnk)",
                4,
            )]
        );
        m.insert(
            "system_keywords",
            vec![(
                r"(cmd.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log)",
                5,
            )]
        );
        m.insert(
            "protocol_keywords",
            vec![(r"(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)", 5)],
        );
        m.insert(
            "connection_keywords",
            vec![(r"(error|http|closed|fail|version|proxy)", 3)],
        );
        m.insert(
            "temp_and_recycler",
            vec![(r"(TEMP|Temporary|Appdata|Recycler)", 4)],
        );
        m.insert(
            "malicious_keywords",
            vec![(
                r"(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|credentials|creds|coded|p0c|Content|host)",
                5,
            )]
        );
        m.insert(
            "network_keywords",
            vec![(
                r"(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection)",
                3,
            )]
        );
        m.insert("drive", vec![(r"([C-Zc-z]:\\)", 4)]);
        m.insert(
            "IP",
            vec![(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                5,
            )]
        );
        m.insert(
            "copyright",
            vec![(r"(coded | c0d3d |cr3w\b|Coded by |codedby)", 7)],
        );
        m.insert("extensions_generic", vec![(r"\.[a-zA-Z]{3}\b", 3)]);
        m.insert("alll_characters", vec![(r"^[A-Z][a-z]{5,}$", 2)]);
        m.insert(
            "URL",
            vec![(
                r"(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)",
                2,
            )],
        );
        m.insert(
            "certificates",
            vec![(
                r"(thawte|trustcenter|signing|class|crl|certificate|assembly)",
                -4,
            )],
        );
        m.insert(
            "parameters1",
            vec![(r"( \-[a-z]{0,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)", 4)],
        );
        m.insert("directory", vec![(r"([a-zA-Z]:|^|%)\\[A-Za-z]{4,30}\\", 4)]);
        m.insert(
            "executable_no_dir",
            vec![(r"^[^\\]+\.(exe|com|scr|bat|sys)$", 4)],
        );
        m.insert(
            "date_placeholders",
            vec![(r"(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)", 3)],
        );
        m.insert(
            "placeholders",
            vec![(r"[^A-Za-z](%s|%d|%i|%02d|%04d|%2d|%3s)[^A-Za-z]", 3)],
        );
        m.insert(
            "string_parts",
            vec![(
                r"(cmd|com|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)",
                3,
            )],
        );
        m.insert(
            "programming",
            vec![(
                r"(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)",
                3,
            )]
        );
        m.insert(
            "credentials",
            vec![(
                r"(user|pass|login|logon|token|cookie|creds|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|identif|account|login|auth|privilege)",
                3,
            )]
        );
        m.insert("malware", vec![(r"(\.[a-z]/[^/]+\.txt)", 3)]);
        m.insert("variables", vec![(r"%[A-Z_]+%", 4)]);
        m.insert(
            "RATs",
            vec![(
                r"(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|metasploit|/veil|Blood)",
                5,
            )]
        );
        m.insert("paths", vec![(r"^[Cc]:\\\\[^PW]", 3)]);
        m.insert(
            "missed_user_profiles",
            vec![(
                r"[\\](users|profiles|username|benutzer|Documents and Settings|Utilisateurs|Utenti|Usuários)[\\]",
                3,
            )]
        );
        m.insert("strings_with_numbers", vec![(r"^[A-Z][a-z]+[0-9]+$", 1)]);
        m.insert("spying", vec![(r"(implant)", 1)]);
        m.insert(
            "special_strings",
            vec![(r"(\\\\\.\\|kernel|.dll|usage|\\DosDevices\\)", 5)],
        );
        m.insert(
            "parameters",
            vec![(
                r"( \-[a-z] | /[a-z] | \-[a-z]:[a-zA-Z]| \/[a-z]:[a-zA-Z])",
                4,
            )],
        );
        m.insert("file", vec![(r"^[a-zA-Z0-9]{3,40}\.[a-zA-Z]{3}", 3)]);
        m.insert(
            "comment",
            vec![(r"^([\*\#]+ |\[[\*\-\+]\] |[\-=]> |\[[A-Za-z]\] )", 4)],
        );
        m.insert(
            "typo",
            vec![(r"(!\.$|!!!$| :\)$| ;\)$|fucked|[\w]\.\.\.\.$)", 4)],
        );
        m.insert(
            "base64",
            vec![(
                r"^(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
                7,
            )],
        );
        m.insert(
            "b64exec",
            vec![(
                r"(TVqQAAMAAAAEAAAA//8AALgAAAA|TVpQAAIAAAAEAA8A//8AALgAAAA|TVqAAAEAAAAEABAAAAAAAAAAAAA|TVoAAAAAAAAAAAAAAAAAAAAAAAA|TVpTAQEAAAAEAAAA//8AALgAAAA)",
                5,
            )]
        );
        m.insert(
            "malicious_intent",
            vec![(
                r"(loader|cmdline|ntlmhash|lmhash|infect|encrypt|exec|elevat|dump|target|victim|override|traverse|mutex|pawnde|exploited|shellcode|injected|spoofed|dllinjec|exeinj|reflective|payload|inject|back conn)",
                5,
            )]
        );
        m.insert(
            "privilege",
            vec![(
                r"(administrator|highest|system|debug|dbg|admin|adm|root) privelege",
                4,
            )],
        );
        m.insert(
            "system_file",
            vec![(r"(LSASS|SAM|lsass.exe|cmd.exe|LSASRV.DLL)", 4)],
        );
        m.insert("compiler", vec![(r"(Release|Debug|bin|sbin)", 2)]);
        m.insert("pe_exe", vec![(r"(\.exe|\.dll|\.sys)$", 4)]);
        m.insert("string_valid", vec![(r"(^\\\\)", 1)]);
        m.insert(
            "malware_related",
            vec![(
                r"(Management Support Team1|/c rundll32|DTOPTOOLZ Co.|net start|Exec|taskkill)",
                4,
            )],
        );
        m.insert(
            "powershell",
            vec![(
                r"(bypass|windowstyle | hidden |-command|IEX |Invoke-Expression|Net.Webclient|Invoke[A-Z]|Net.WebClient|-w hidden |-encoded-encodedcommand| -nop |MemoryLoadLibrary|FromBase64String|Download|EncodedCommand)",
                4,
            )]
        );
        m.insert("wmi", vec![(r"( /c WMIC)", 3)]);
        m.insert(
            "windows_commands",
            vec![(
                r"( net user | net group |ping |whoami |bitsadmin |rundll32.exe javascript:|schtasks.exe /create|/c start )",
                3,
            )]
        );
        m.insert(
            "signing_certificates",
            vec![(r"( Inc | Co.|  Ltd.,| LLC| Limited)", 2)],
        );
        m.insert(
            "privilege_escalation",
            vec![(r"(sysprep|cryptbase|secur32)", 2)],
        );
        m.insert(
            "webshells",
            vec![(r"(isset\($post\[|isset\($get\[|eval\(Request)", 2)],
        );
        m.insert(
            "suspicious_words",
            vec![(
                r"(impersonate|drop|upload|download|execute|shell|\bcmd\b|decode|rot13|decrypt)",
                2,
            )],
        );
        m.insert(
            "suspicious_words2",
            vec![(
                r"([+] |[-] |[*] |injecting|exploit|dumped|dumping|scanning|scanned|elevation|elevated|payload|vulnerable|payload|reverse connect|bind shell|reverse shell| dump |back connect |privesc|privilege escalat|debug privilege| inject |interactive shell|shell commands| spawning |] target |] Transmi|] Connect|] connect|] Dump|] command |] token|] Token |] Firing | hashes | etc/passwd| SAM | NTML|unsupported target|race condition|Token system |LoaderConfig| add user |ile upload |ile download |Attaching to |ser has been successfully added|target system |LSA Secrets|DefaultPassword|Password: |loading dll|.Execute\(|Shellcode|Loader|inject x86|inject x64|bypass|katz|spoit|ms[0-9][0-9][^0-9]|\bCVE[^a-zA-Z]|privilege::|lsadump|door)",
                4,
            )]
        );
        m.insert(
            "mutex_pipes",
            vec![(r"(Mutex|NamedPipe|\\Global\\|\\pipe\\)", 3)],
        );
        m.insert("usage", vec![(r"(isset\($post\[|isset\($get\[)", 2)]);
        m.insert(
            "hash",
            vec![(r"\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", 2)],
        );
        m.insert(
            "persistence",
            vec![(r"(sc.exe |schtasks|at \\\\|at [0-9]{2}:[0-9]{2})", 3)],
        );
        m.insert(
            "unix",
            vec![(
                r"(;chmod |; chmod |sh -c|/dev/tcp/|/bin/telnet|selinux| shell| cp /bin/sh )",
                3,
            )],
        );
        m.insert(
            "attack",
            vec![(
                r"(attacker|brute force|bruteforce|connecting back|EXHAUSTIVE|exhaustion| spawn| evil| elevated)",
                3,
            )]
        );
        m.insert(
            "less_value",
            vec![(
                r"(abcdefghijklmnopqsst|ABCDEFGHIJKLMNOPQRSTUVWXYZ|0123456789:;)",
                -5,
            )],
        );
        m.insert(
            "vb_backdoors",
            vec![(r"(kill|wscript|plugins|svr32|Select )", 3)],
        );
        m.insert(
            "susp_strings_combo",
            vec![(r"([a-z]{4,}[!\?]|\[[!+\-]\] )", 3)],
        );
        m.insert("special_chars", vec![(r"(-->|!!!| <<< | >>> )", 5)]);
        m.insert("swear", vec![(r"\b(fuck|damn|shit|penis|nigger)\b", 5)]);
        m.insert(
            "scripts",
            vec![(
                r"(%APPDATA%|%USERPROFILE%|Public|Roaming|& del|& rm| && |script)",
                3,
            )],
        );
        m.insert("uacme", vec![(r"(Elevation|pwnd|pawn|elevate to)", 3)]);
        m.insert("dots", vec![(r"(\.\.)", -5)]);
        m.insert("spaces", vec![(r"(  )", -5)]);
        let mut compiled_m = HashMap::new();
        for (key, patterns) in m {
            let compiled_patterns: Vec<(Regex, i64)> = patterns
                .into_iter()
                .map(|(pattern, score)| (Regex::new(pattern).unwrap(), score))
                .collect();
            compiled_m.insert(key, compiled_patterns);
        }
        compiled_m
    };
    pub static ref REGEX_SENSITIVE: RegexRules = {
        let mut m = HashMap::new();
        m.insert("reduce", vec![(r"(?i)(rundll32\.exe$|kernel\.dll$)", -4)]);
        m.insert("all_caps", vec![(r"^[A-Z]{6,}$", 3)]);
        m.insert("all_lower", vec![(r"^[a-z]{6,}$", 3)]);
        m.insert("all_lower_with_space", vec![(r"^[a-z\s]{6,}$", 2)]);
        m.insert( "javascript", vec![(r"\(new ActiveXObject\(. WScript.Shell.\).Run|.Run\(.cmd.exe|.Run\(.%comspec%\)|.Run\(.c:\\Windows|.RegisterXLL\(\)", 3 )]);
        m.insert(
            "ua_keywords",
            vec![(
                r"(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)",
                5,
            )],
        );
        m.insert("packers", vec![(r"(WinRAR\\SFX)", -4)]);
        m.insert("US_ASCII_char", vec![(r"\x1f", -4)]);
        m.insert("repeated_chars", vec![(r"(.* ([A-Fa-f0-9]){8,})", -5)]);
        m.insert("nulls", vec![(r"(00000000)", -5)]);
        let mut compiled_m = HashMap::new();
        for (key, patterns) in m {
            let compiled_patterns: Vec<(Regex, i64)> = patterns
                .into_iter()
                .map(|(pattern, score)| (Regex::new(pattern).unwrap(), score))
                .collect();
            compiled_m.insert(key, compiled_patterns);
        }
        compiled_m
    };
}

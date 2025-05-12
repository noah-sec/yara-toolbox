// Rule to detect Tailscale executable files by path. This is set to critical severity because Tailscale can be used for file exfiltration.
rule Tailscale_Executable_Paths
{
    meta:
        description = "Detects Tailscale executable files in common installation paths"
         autora = "Noah Grayson"
        date = "2025-05-13"
        severity = "Critical"
    strings:
        $path1 = "C:\\Program Files\\Tailscale\\tailscale.exe" ascii wide
        $path2 = "C:\\Program Files\\Tailscale\\tailscaled.exe" ascii wide
    condition:
        any of them
}

// Rule to detect running Tailscale processes by name. This is set to critical severity because Tailscale can be used for file exfiltration.
rule Tailscale_Running_Process
{
    meta:
        description = "Detects running Tailscale processes"
        autora = "Noah Grayson"
        date = "2025-05-13"
        severity = "Critical"
    strings:
        $proc1 = "tailscale.exe" ascii wide
        $proc2 = "tailscaled.exe" ascii wide
    condition:
        for any $str in ($proc1, $proc2) : ( filepath(pe.rule, $str) or proc.name == $str )
}

/*
   annaconda — committed YARA baseline.

   Referenced by the `yara_process` / `yara_file` templates through the
   RuleSet parameter (name only; rule text is never accepted from a caller).

   Scope note, stated because it bounds every match these rules produce:
   signature matching answers "do these bytes appear here", not "is this host
   compromised". The adversary chooses the bytes. A match collected through
   these templates is sealed as evidence and carries no verdict weight — see
   the design note in vql_templates.py.
*/

rule annaconda_purple_team_marker
{
    meta:
        author      = "annaconda"
        description = "Harmless marker for exercising the YARA collection path end to end"
        purpose     = "self-test"
        reference   = "write the marker string to a file, scan it, watch it seal"

    strings:
        $marker = "ANNACONDA-PURPLE-TEAM-YARA-SELFTEST"

    condition:
        $marker
}

rule credential_dumper_strings
{
    meta:
        author      = "annaconda"
        description = "Distinctive strings from widely used credential-dumping tooling"
        mitre       = "T1003.001"
        confidence  = "indicator, not conclusion"

    strings:
        // Distinctive enough to be worth flagging, generic enough to be a
        // candidate rather than proof. Note the obvious self-match: scanning
        // a directory that contains this rule file will match this rule.
        $cmd1 = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd2 = "lsadump::sam" ascii wide nocase
        $tool = "gentilkiwi" ascii wide nocase

    condition:
        any of them
}

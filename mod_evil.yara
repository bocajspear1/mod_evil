rule mod_evil_apache_module {
meta:
    description = "Rule to detect mod_evil.so"
    author = "Jacob Hartman"
    date = "2022/07/30"
strings:
    $elf = "ELF"
    $s1 = "popen" fullword ascii
    $s2 = "ap_rprintf" fullword ascii
    $s3 = "ap_hook_quick_handler" fullword ascii
    $s4 = "creat" fullword ascii
condition:
    ( $elf at 1 ) and $s1 and $s2 and $s3 and $s4
}
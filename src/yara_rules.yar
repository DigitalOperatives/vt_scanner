/*
    This is a test rule for yara
*/

rule test_rule0
{
    strings:
        $test_hex_string = {48 8D 74 24 78 48 8D 7C 24 7C 44 89 E9 BA 02 00}
        
    condition:
        $test_hex_string
}

rule test_rule1
{
    strings:
        $test_hex_string = {06 48 8F 03 8E 04 8D 05 8C 06 44 83 07 03 08 01}
    
    condition:
        $test_hex_string
}

rule eicar
{
    strings:
        $eicar_string = {45 49 43 41 52 2D 53 54 41}
        
    condition:
        $eicar_string
}

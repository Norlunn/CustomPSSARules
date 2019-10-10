function Test-KeyWordCasing {
    $num = 1..3
    foreach ($n in $num) {
        If ($n -EQ 2) {
            "Two"
        }
        ElseIf ($n -eq 3) {
            "Three"
        }
        Else {
            "One!"
        }
    }
}
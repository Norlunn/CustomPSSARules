function Test-KeyWordCasing {
    $num = 1..3
    foreach ($n in $num) {
        if ($n -eq 2) {
            "Two"
        }
        elseif($n -eq 3 -or -not ($n -like "*OK*") -or $n -in 1..10 -or $n -match ("3" -repLace "4") -and $true) {
            "Three"
        }
        else{
            "One"
        }
    }
}
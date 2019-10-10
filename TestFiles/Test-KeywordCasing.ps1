function Test-KeyWordCasing {
    $num = 1..3
    foreach ($n in $num) {
        if ($n -EQ 2) {
            "Two"
        }
        elseif($n -eq 3) {
            "Three"
        }
        else{
            "One!"
        }
    }
}
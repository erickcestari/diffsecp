#!/bin/sh
# Rewrites the block between the coverage markers in a README from an llvm-cov
# report: one row per libsecp file with code, and totals over those files,
# followed by the line in SCORE (`make mutation-score`). The block names the
# libsecp commit rather than a date, so it only changes when coverage does.
#
# usage: readme-coverage.sh REPORT SECP README SCORE
set -eu

report=$1 secp=$2 readme=$3 score=$4
commit=$(git -C "$secp" rev-parse --short=12 HEAD)
table=$(mktemp)
trap 'rm -f "$table" "$readme.tmp"' EXIT

# Report columns: file, regions (total, missed, %), functions (total, missed, %),
# lines (total, missed, %), branches (total, missed, %).
awk -v prefix="$secp/" -v commit="$commit" -v score="$(cat "$score")" '
    function pct(total, missed) { return total ? sprintf("%.2f%%", 100 * (total - missed) / total) : "-" }
    index($1, prefix) == 1 && NF == 13 && $8 > 0 {
        rows = rows sprintf("| `%s` | %s | %s | %s |\n", substr($1, length(prefix) + 1), $10, $13, $7)
        lines += $8; lines_missed += $9
        branches += $11; branches_missed += $12
        functions += $5; functions_missed += $6
    }
    END {
        print ""
        printf "libsecp `%s`: %s of lines, %s of branches, %s of functions.\n\n", commit,
               pct(lines, lines_missed), pct(branches, branches_missed), pct(functions, functions_missed)
        printf "%s\n\n", score
        print "| File | Lines | Branches | Functions |"
        print "|------|------:|---------:|----------:|"
        printf "%s\n", rows
    }' "$report" > "$table"

grep -q '^<!-- coverage:begin -->$' "$readme" && grep -q '^<!-- coverage:end -->$' "$readme" || {
    echo "readme-coverage.sh: $readme lacks the coverage markers" >&2
    exit 1
}
awk -v table="$table" '
    /^<!-- coverage:end -->$/ { while ((getline row < table) > 0) print row; skip = 0 }
    !skip { print }
    /^<!-- coverage:begin -->$/ { skip = 1 }' "$readme" > "$readme.tmp"
mv "$readme.tmp" "$readme"

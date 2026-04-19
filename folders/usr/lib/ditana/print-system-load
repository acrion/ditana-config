#!/usr/bin/env bash

# Copyright (c) 2024, 2025 acrion innovations GmbH
# Authors: Stefan Zipproth, s.zipproth@acrion.ch
#
# This file is part of ditana-print-system-load, see https://github.com/acrion/ditana-print-system-load
#
# ditana-print-system-load is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ditana-print-system-load is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with ditana-print-system-load. If not, see <https://www.gnu.org/licenses/>.

trim() {
    local var="$*"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    echo -n "$var"
}

format_fixed_length() {
    local input="$1"
    local fixed_length=16
    local output="${input:0:fixed_length}"
    while [[ ${#output} -lt $fixed_length ]]; do
        output+=" "
    done
    echo -n "$output"
}

print_load() {
    local load="$(printf "%.0f" "$1")"
    local empty_blocks="$(echo "$cores - $load" | bc -l)"

    if (( $(echo "$load >= $cores" | bc) )); then
        load=$cores
        empty_blocks=0
    fi

    if (( $(echo "$load > 0" | bc) )); then
        for ((i=1; i<=load; i++)); do
            printf '%d' $((i % 10)) # alternative: \xE2\x96\xA3 (▣)
        done

    fi

    if (( $(echo "$empty_blocks > 0" | bc) )); then
        printf '%0.s—' $(seq 1 "$empty_blocks") # alternative: \xE2\x96\xA2 (▢)
    fi
}

LC_MESSAGES=C.UTF-8 virtualcores=$(trim "$(lscpu | grep -E '^CPU\(s\):' | awk '{print $2}')")
cores=$(trim "$(lscpu | grep -E '^Core\(' | awk '{print $4}')")

cpu_load=$(COLUMNS=1000 top -bn1 | grep '%Cpu' | awk -F', ?' -v virtualcores="$virtualcores" '{gsub(/[[:space:]]+id/, "", $4); printf "%f\n", (100-$4)*virtualcores/100}')
process_name=$(COLUMNS=1000 top -b -n 1 | head -n 8 | tail -n 1 | cut -c 72-)

load_output=$(print_load "$cpu_load")

if [[ "$process_name" != "top" ]] && (( $(echo "$cpu_load >= $cores/10" |bc -l) )) ; then
    process_name_output=$(format_fixed_length "$process_name")
else
    process_name_output=$(format_fixed_length " ")
fi

free_ram=$(awk '/MemAvailable/ {printf "%.2f GB", $2 / 1024 / 1024}' /proc/meminfo)

printf "%.16s\n%s\n%s" "$process_name_output" "$load_output" "$free_ram"

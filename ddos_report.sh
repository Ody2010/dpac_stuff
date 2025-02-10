#!/bin/bash
#
# ddos_report.sh - Generate a report evidencing a DDoS or high-traffic attack.

# ---------------
# USER INPUTS
# ---------------

# Prompt for log pattern
read -p "Enter log file pattern (e.g., *-ssl_log-Jan-2025.gz): " LOG_PATTERN

# Prompt for start and end time with sample format
echo "Please enter the start and end times in the following format: DD/Mon/YYYY:HH:MM:SS"
read -p "Enter start time (e.g., 26/Jan/2025:10:00:00): " START
read -p "Enter end time (e.g., 26/Jan/2025:13:00:00): " END

# Validate inputs
if [[ -z "$LOG_PATTERN" || -z "$START" || -z "$END" ]]; then
  echo "Error: All inputs (log pattern, start, and end time) are required."
  exit 1
fi

# Output file for the report
REPORT_FILE="/tmp/ddos_report.txt"
LOG_ERROR_FILE="/tmp/ddos_script_error.log"

# ---------------
# BEGIN REPORTING
# ---------------

{
  echo "DDoS / High Traffic Analysis Report"
  echo "Time Window: $START to $END"
  echo "Log Pattern: $LOG_PATTERN"
  echo "Generated on: $(date)"
  echo "-----------------------------------------------------"
} > "$REPORT_FILE"

# Find logs
LOG_FILES=$(find /home/*/logs/ -type f -name "$LOG_PATTERN" 2> "$LOG_ERROR_FILE")

# Exit if no logs are found
if [[ -z "$LOG_FILES" ]]; then
  echo "No matching logs found. Please check the pattern: $LOG_PATTERN" >> "$REPORT_FILE"
  echo "No matching logs found. See $REPORT_FILE for details."
  exit 1
fi

# Process logs
zcat $LOG_FILES | \
gawk -v start="$START" -v end="$END" '
BEGIN { total = 0 }
{
  # Extract timestamp
  if (match($0, /\[([0-9]{2}\/[A-Za-z]{3}\/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2})/, arr)) {
    ts = arr[1]
    if (ts >= start && ts <= end) {
      total++
      # Extract IP
      if (match($0, /^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, ip_arr)) {
         ip = ip_arr[1]
         ip_hits[ip]++
         split(ip, octets, ".")
         subnet24 = octets[1] "." octets[2] "." octets[3]
         subnet24_hits[subnet24]++
         subnet16 = octets[1] "." octets[2]
         subnet16_hits[subnet16]++
      }
    }
  }
}
END {
  printf "Total requests in time window: %d\n\n", total

  if (total == 0) {
    print "No requests found in the given time window."
    exit
  }

  printf "Top Individual IP Addresses:\n%-18s %8s %12s\n-------------------------------------------\n", "IP Address", "Hits", "Traffic %"
  n = asorti(ip_hits, sorted_ips, "@val_num_desc")
  for (i = 1; i <= (n > 10 ? 10 : n); i++) {
    ip = sorted_ips[i]
    printf "%-18s %8d %11.2f%%\n", ip, ip_hits[ip], (ip_hits[ip] / total) * 100
  }

  printf "\nTop Subnets (/24):\n%-18s %8s %12s\n-------------------------------------------\n", "Subnet", "Hits", "Traffic %"
  m = asorti(subnet24_hits, sorted_subnets24, "@val_num_desc")
  for (i = 1; i <= (m > 10 ? 10 : m); i++) {
    s24 = sorted_subnets24[i]
    printf "%-18s %8d %11.2f%%\n", s24, subnet24_hits[s24], (subnet24_hits[s24] / total) * 100
  }

  printf "\nTop Subnets (/16):\n%-18s %8s %12s\n-------------------------------------------\n", "Subnet", "Hits", "Traffic %"
  k = asorti(subnet16_hits, sorted_subnets16, "@val_num_desc")
  for (i = 1; i <= (k > 10 ? 10 : k); i++) {
    s16 = sorted_subnets16[i]
    printf "%-18s %8d %11.2f%%\n", s16, subnet16_hits[s16], (subnet16_hits[s16] / total) * 100
  }
}
' >> "$REPORT_FILE"

# ---------------
# FINISH & NOTIFY
# ---------------

echo "Report complete! See $REPORT_FILE for details."

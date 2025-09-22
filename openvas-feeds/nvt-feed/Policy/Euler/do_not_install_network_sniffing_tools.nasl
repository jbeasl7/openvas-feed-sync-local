# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130458");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Install Network Sniffing Tools");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.15 Do Not Install Network Sniffing Tools (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.15 Do Not Install Network Sniffing Tools (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.15 Do Not Install Network Sniffing Tools (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.15 Do Not Install Network Sniffing Tools (Requirement)");

  script_tag(name:"summary", value:"If network sniffing tools exist in the production environment,
attackers may use them for network analysis and attacks. Therefore, in the production environment,
do not install network sniffing, packet capturing, or analysis tools, such as tcpdump, Ethereal,
and Wireshark.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Install Network Sniffing Tools";

solution = 'If network sniffing software is installed in the service environment, run the rpm
command to search for and delete related software packages. For example, run the following command
to delete Nmap:

# rpm -e nmap

You can also run the rm command to manually delete the Nmap files. This method is applicable if
Nmap is not installed using an RPM package. Ensure that all related files are deleted.

# rm /usr/bin/nmap';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# rpm -qa | grep -iE "(^|[0-9]+:)(wireshark|wireshark-cli|wireshark-qt|tshark|tcpdump|nmap|nmap-ncat|ncat|netcat|openbsd-netcat|gnu-netcat|dsniff|ettercap|aircrack-ng|kismet|hping3?|python3-scapy|scapy|snort|zeek|bro|netsniff-ng|ngrep|iftop|iptraf(-ng)?|etherape|packit|paros)(-|$)"

2. Run the command in the terminal:
# PATH_DIRS="/bin /sbin /usr/bin /usr/sbin /usr/local/bin"; for d in $PATH_DIRS; do find "$d" -type f \\( -name "wireshark" -o -name "tshark" -o -name "tcpdump" -o -name "nmap" -o -name "ncat" -o -name "netcat" -o -name "dsniff" -o -name "ettercap" -o -name "aircrack-ng" -o -name "kismet" -o -name "hping" -o -name "hping3" -o -name "scapy" -o -name "snort" -o -name "zeek" -o -name "bro" -o -name "netsniff-ng" -o -name "ngrep" -o -name "iftop" -o -name "iptraf" -o -name "iptraf-ng" -o -name "etherape" -o -name "packit" -o -name "paros" -o -name "dumpcap" -o -name "editcap" -o -name "mergecap" -o -name "capinfos" \\) 2>/dev/null | while read f; do file "$f" 2>/dev/null | grep -qi "ELF" && echo "$f"; done; done

3. Run the command in the terminal:
# ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE "\\b(wireshark|tshark|tcpdump|ncat|netcat|nmap|dsniff|ettercap|aircrack-ng|kismet|hping|hping3|scapy|snort|zeek|bro|netsniff-ng|ngrep|iftop|iptraf|iptraf-ng|etherape|packit|paros)\\b" | grep -v "grep"

4. Run the command in the terminal:
# ss -tulpn 2>/dev/null | grep -iE "users:\\(\\(\\"(wireshark|tshark|tcpdump|ncat|netcat|nmap|dsniff|ettercap|aircrack-ng|kismet|hping|hping3|scapy|snort|zeek|bro|netsniff-ng|ngrep|iftop|iptraf|iptraf-ng|etherape|packit|paros)"';

expected_value = '1. The output should be empty
2. The output should be empty
3. The output should be empty
4. The output should be empty';

# ------------------------------------------------------------------
# CONNECTION CHECK
# ------------------------------------------------------------------

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){

  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

overall_pass = FALSE;
actual_value = "";

# ------------------------------------------------------------------
# CHECK 1 :  Check on rpm systems
# ------------------------------------------------------------------

step_cmd_check_1 = 'rpm -qa | grep -iE "(^|[0-9]+:)(wireshark|wireshark-cli|wireshark-qt|tshark|tcpdump|nmap|nmap-ncat|ncat|netcat|openbsd-netcat|gnu-netcat|dsniff|ettercap|aircrack-ng|kismet|hping3?|python3-scapy|scapy|snort|zeek|bro|netsniff-ng|ngrep|iftop|iptraf(-ng)?|etherape|packit|paros)(-|$)"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(!step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check binaries in the filesystem
# ------------------------------------------------------------------

step_cmd_check_2 = 'PATH_DIRS="/bin /sbin /usr/bin /usr/sbin /usr/local/bin"; for d in $PATH_DIRS; do find "$d" -type f \\( -name "wireshark" -o -name "tshark" -o -name "tcpdump" -o -name "nmap" -o -name "ncat" -o -name "netcat" -o -name "dsniff" -o -name "ettercap" -o -name "aircrack-ng" -o -name "kismet" -o -name "hping" -o -name "hping3" -o -name "scapy" -o -name "snort" -o -name "zeek" -o -name "bro" -o -name "netsniff-ng" -o -name "ngrep" -o -name "iftop" -o -name "iptraf" -o -name "iptraf-ng" -o -name "etherape" -o -name "packit" -o -name "paros" -o -name "dumpcap" -o -name "editcap" -o -name "mergecap" -o -name "capinfos" \\) 2>/dev/null | while read f; do file "$f" 2>/dev/null | grep -qi "ELF" && echo "$f"; done; done';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(!step_res_check_2){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Check running processes
# ------------------------------------------------------------------

step_cmd_check_3 = 'ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE "\\b(wireshark|tshark|tcpdump|ncat|netcat|nmap|dsniff|ettercap|aircrack-ng|kismet|hping|hping3|scapy|snort|zeek|bro|netsniff-ng|ngrep|iftop|iptraf|iptraf-ng|etherape|packit|paros)\\b" | grep -v "grep"';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(!step_res_check_3){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 4 :  Check Listening Ports
# ------------------------------------------------------------------

step_cmd_check_4 = 'ss -tulpn 2>/dev/null | grep -iE "users:\\(\\(\\"(wireshark|tshark|tcpdump|ncat|netcat|nmap|dsniff|ettercap|aircrack-ng|kismet|hping|hping3|scapy|snort|zeek|bro|netsniff-ng|ngrep|iftop|iptraf|iptraf-ng|etherape|packit|paros)"';
step_res_check_4 = ssh_cmd(socket:sock, cmd:step_cmd_check_4, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '4. ' + step_res_check_4 + '\n';
check_result_4 = FALSE;

if(!step_res_check_4){
  check_result_4 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2 && check_result_3 && check_result_4){
  overall_pass = TRUE;
}

if(overall_pass){
  compliant = "yes";
  comment = "All checks passed";
}else{
  compliant = "no";
  comment = "One or more checks failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);

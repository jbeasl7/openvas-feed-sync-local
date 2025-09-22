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
  script_oid("1.3.6.1.4.1.25623.1.0.130373");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:21 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the chronyd Service Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.6 Time Synchronization: 3.6.2 Configure the chronyd Service Properly (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.6 Time Synchronization: 3.6.2 Configure the chronyd Service Properly (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.6 Time Synchronization: 3.6.2 Configure the chronyd Service Properly (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.6 Time Synchronization: 3.6.2 Configure the chronyd Service Properly (Recommendation)");

  script_tag(name:"summary", value:"If the time server is incorrectly configured, the time of the
local server may be inconsistent with that of other servers or the standard time. If time is
incorrect, services that strongly depend on time synchronization, such as market transactions, may
be interrupted, and attackers may exploit the time difference to tamper with or forge data.

chrony is free open source software. Similar to the conventional NTP service, chrony synchronizes
the system clock with the time server to ensure time accuracy. chrony consists of two programs:
chronyd and chronyc.

chronyd is a daemon running in the background. It is used to synchronize the system clock running
in the kernel with the time server. chronyd determines the time offset of the computer and make
compensation accordingly.

chronyc provides a CLI for monitoring performance and performing configurations. It can work on a
computer running the chronyd service or on a remote computer.

If you choose chronyd as the time synchronization service based on the service scenario, you need
to correctly configure the remote time server and enable the chronyd service.

chrony and NTP are interchangeable. By default, the chronyd service is enabled in openEuler.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure the chronyd Service Properly";

solution = '1. Add the correct IP address of the time server to the pool or server field in the
/etc/chrony.conf file. If there are multiple time servers, you can configure multiple IP addresses
based on the priority.
# vim /etc/chrony.conf
server <IP address>
server <IP address>

2. Run the service command to start the chronyd service and check the service status.
# service chronyd start
Redirecting to /bin/systemctl start chronyd.service
# service chronyd status 2>&1 <pipe> grep Active
   Active: active (running) since Tue 2020-12-01 14:47:49 CST<semicolon> 1min 6s ago';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# grep "^server\\|^pool" /etc/chrony.conf

2. Run the command in the terminal:
# ps -ef | grep [c]hronyd';

expected_value = '1. The output should not be empty
2. The output should not be empty';

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
# CHECK 1 :  Verify command `grep "^server\\|^pool" /etc/chrony.conf`
# ------------------------------------------------------------------

step_cmd_check_1 = 'grep "^server\\|^pool" /etc/chrony.conf';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `ps -ef | grep [c]hronyd`
# ------------------------------------------------------------------

step_cmd_check_2 = 'ps -ef | grep [c]hronyd';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2){
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
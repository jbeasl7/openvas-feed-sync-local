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
  script_oid("1.3.6.1.4.1.25623.1.0.130407");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Restrict the Number of Historical Command Records");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.1 Restrict the Number of Historical Command Records (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.1 Restrict the Number of Historical Command Records (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.1 Restrict the Number of Historical Command Records (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.1 Restrict the Number of Historical Command Records (Recommendation)");

  script_tag(name:"summary", value:"HISTSIZE is an environment variable used to control the size of
the command history. Specifically, HISTSIZE defines the number of command entries that can be
stored in the command history. By setting the value of HISTSIZE, you can limit or increase the size
of the command history, thus controlling the number of previously entered commands available in the
command line terminal.

For example, if HISTSIZE is set to 100, a maximum of 100 commands can be stored in the command
history. Once the command history reaches this limit, the new command overwrites the oldest command
to keep the history size within the specified value.

Function: Small historical records reduce the risk that sensitive information (such as passwords)
is retained in historical records.

It is recommended that the system limit the number of historical commands to be viewed to 50 or 100.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Restrict the Number of Historical Command Records";

solution = 'Check the value of the environment variable HISTSIZE in the profile file. Run the
following commands to set the number of historical commands to a value ranging from 1 to 100 and
make the setting take effect:

# grep -qiP "^HISTSIZE" /etc/profile && sed -i "/^HISTSIZE/cHISTSIZE=100" /etc/profile <pipe><pipe>
echo -e "HISTSIZE=100" >> /etc/profile

# source /etc/profile';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# bash -l -c \'echo \\$HISTSIZE\'

2. Run the command in the terminal:
# grep -vE "^\\s*#" /etc/profile | grep -o -iP "HISTSIZE=\\K.+" | tail -n 1';

expected_value = '1. The output should higher than or equal to "1" and less than or equal to "100"
2. The output should higher than or equal to "1" and less than or equal to "100"';

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
# CHECK 1 :  Verify command `bash -l -c \'echo \\$HISTSIZE\'`
# ------------------------------------------------------------------

step_cmd_check_1 = 'bash -l -c \'echo \\$HISTSIZE\'';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(int(step_res_check_1) >= int(1) && int(step_res_check_1) <= int(100)){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `grep -vE "^\\s*#" /etc/profile | grep -o -iP "HISTSIZE=\\K.+" | tail -n 1`
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -vE "^\\s*#" /etc/profile | grep -o -iP "HISTSIZE=\\K.+" | tail -n 1';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(int(step_res_check_2) >= int(1) && int(step_res_check_2) <= int(100)){
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
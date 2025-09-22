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
  script_oid("1.3.6.1.4.1.25623.1.0.130337");
  script_version("2025-07-09T05:43:50+0000");
  script_tag(name:"last_modification", value:"2025-07-09 05:43:50 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Disable SysRq");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.21 Disable SysRq (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.21 Disable SysRq (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.21 Disable SysRq (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.21 Disable SysRq (Requirement)");

  script_tag(name:"summary", value:"SysRq enables users with physical access to access dangerous
system-level commands in a computer. Therefore, it is advised to restrict the usage of the SysRq
function.

If SysRq is not disabled, you can use the keyboard to trigger SysRq. As a result, commands may be
directly sent to the kernel, which affects the system.

SysRq is disabled by default in openEuler.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Disable SysRq";

solution = 'Check the settings of the current system kernel parameters. Run the following command
and check the command output. If the configured value of the sysrq parameter is 0, SysRq is
disabled.
Otherwise, the configuration is incorrect. You are advised to modify the configuration file.

# cat /proc/sys/kernel/sysrq
0

Run the following command and check the command output. If the configured value is not 0, the
configuration is incorrect. You are advised to modify the configuration file.
If the configured value is empty, the system uses the default configuration (the default value 0).

# grep <quote>^kernel.sysrq<quote> /etc/sysctl.conf /etc/sysctl.d/*
/etc/sysctl.conf:kernel.sysrq=0
/etc/sysctl.d/99-sysctl.conf:kernel.sysrq=0';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# cat /proc/sys/kernel/sysrq 2>/dev/null

2. Run the command in the terminal:
# grep -HnE "^\\s*kernel\\.sysrq\\s*=\\s*0\\s*$" /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf 2>/dev/null';

expected_value = '1. The output should be equal to "0"
2. The output should contain "kernel.sysrq=0"';

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
# CHECK 1 :  Current Runtime Kernel Value
# ------------------------------------------------------------------

step_cmd_check_1 = 'cat /proc/sys/kernel/sysrq 2>/dev/null';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == "0"){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check Permanent Configuration Value
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -HnE "^\\s*kernel\\.sysrq\\s*=\\s*0\\s*$" /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf 2>/dev/null';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, "kernel.sysrq=0")){
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
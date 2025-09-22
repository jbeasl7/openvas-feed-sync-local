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
  script_oid("1.3.6.1.4.1.25623.1.0.130439");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Install Debugging Tools");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.16 Do Not Install Debugging Tools (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.16 Do Not Install Debugging Tools (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.16 Do Not Install Debugging Tools (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.16 Do Not Install Debugging Tools (Requirement)");

  script_tag(name:"summary", value:"Debugging scripts and tools in the service environment may be
exploited by attackers to launch attacks. Therefore, do not install any debugging tools or files in
the production environment. Such tools or files include but not limited to: code debugging
tool<semicolon> privilege escalation commands, scripts, and tools used for debugging<semicolon>
certificates and keys used during debugging<semicolon> perf, breakpoint, and instrumentation tools
used for performance tests<semicolon> attack scripts and tool scripts used for verifying security
issues such as common vulnerabilities and exposures (CVEs). Common open source third-party
debugging tools include strace, GDB, readelf, and perf.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Install Debugging Tools";

solution = 'If debugging software is installed in the service environment, run the rpm command to
search for and delete related software packages. For example, run the following command to delete
GDB:

# rpm -e gdb

You can also run the rm command to manually delete the GDB command files. This method is applicable
if GDB is not installed using an RPM package. Ensure that all related files are deleted.

# rm /usr/bin/gdb';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# rpm -qa | grep -iE "^strace-|^gdb-|^perf-|^binutils-extra|^appict|^kmem_analyzer_tools"

2. Run the command in the terminal:
# find / -type f \\( -name "gdb" -o -name "perf" -o -name "strace" -o -name "readelf" \\)';

expected_value = '1. The output should be empty
2. The output should be empty';

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
# CHECK 1 :  Check for installed RPM packages
# ------------------------------------------------------------------

step_cmd_check_1 = 'rpm -qa | grep -iE "^strace-|^gdb-|^perf-|^binutils-extra|^appict|^kmem_analyzer_tools"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(!step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Search for debug-related command files
# ------------------------------------------------------------------

step_cmd_check_2 = 'find / -type f \\( -name "gdb" -o -name "perf" -o -name "strace" -o -name "readelf" \\)';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(!step_res_check_2){
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
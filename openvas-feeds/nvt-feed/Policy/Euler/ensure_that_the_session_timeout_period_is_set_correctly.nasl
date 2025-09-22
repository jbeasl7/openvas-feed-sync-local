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
  script_oid("1.3.6.1.4.1.25623.1.0.130394");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Session Timeout Period Is Set Correctly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"Timeout", type:"entry", value:"300", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.2 Ensure That the Session Timeout Period Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.2 Ensure That the Session Timeout Period Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.2 Ensure That the Session Timeout Period Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.2 Ensure That the Session Timeout Period Is Set Correctly (Requirement)");

  script_tag(name:"summary", value:"Setting a proper timeout duration of sessions can reduce the
risk of system attacks caused by manual operations of the administrator.

To ensure ease of use of the community version in different scenarios, the session timeout interval
is not configured in openEuler distributions by default. Configure the session timeout interval as
required.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Session Timeout Period Is Set Correctly";

solution = "1. Change the value of the TMOUT field in the /etc/profile file to a proper value
based on the service scenario.

# vim /etc/profile
export TMOUT=<seconds>

2. Run the source command to make the configuration take effect.

# source /etc/profile";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep "^export TMOUT=<timeout_seconds>" /etc/profile';

expected_value = 'The output should be equal to "export TMOUT=<timeout_seconds>"';

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

# ------------------------------------------------------------------
# CHECK : Verify command grep "^export TMOUT=<timeout_seconds>" /etc/profile
# ------------------------------------------------------------------

timeout_seconds = script_get_preference("Timeout");
step_cmd = 'grep "^export TMOUT=' + timeout_seconds + '" /etc/profile';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == 'export TMOUT=' + timeout_seconds){
  compliant = "yes";
  comment = "Check passed";
}else{
  compliant = "no";
  comment = "Check failed";
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
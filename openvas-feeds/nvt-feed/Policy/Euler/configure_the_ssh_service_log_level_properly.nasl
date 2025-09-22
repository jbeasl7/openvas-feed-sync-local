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
  script_oid("1.3.6.1.4.1.25623.1.0.130311");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the SSH Service Log Level Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"Log Level", type:"entry", value:"VERBOSE", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.10 Configure the SSH Service Log Level Properly (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.10 Configure the SSH Service Log Level Properly (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.10 Configure the SSH Service Log Level Properly (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.10 Configure the SSH Service Log Level Properly (Recommendation)");
  script_tag(name:"summary", value:"SSH provides multiple log output levels, such as QUIET, FATAL,
ERROR, INFO, VERBOSE, DEBUG, DEBUG1, DEBUG2, and DEBUG3. A higher log level (such as QUIET or
FATAL) prints less log information. This saves drive space but hinders administrators from auditing
and tracing SSH events. Conversely, a lower log level (such as DEBUG2 or DEBUG3) prints more log
information. As a result, detailed recorded events consume more drive space.

The default log level of openEuler is VERBOSE. You are advised to set a proper log level as
required. You are advised not to set the log level to DEBUG or lower because a large number of logs
will be generated.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure the SSH Service Log Level Properly";

solution = "Open the /etc/ssh/sshd_config file, set LogLevel to a proper level, and restart the
sshd service.

# vim /etc/ssh/sshd_config
LogLevel VERBOSE
# systemctl restart sshd";

check_type = "SSH_Cmd";

log_level = script_get_preference("Log Level");

action = 'Run the command in the terminal:
# grep -i "^\\s*LogLevel "'+ log_level +' /etc/ssh/sshd_config 2>/dev/null | grep -vE "^\\s*#"';

expected_value = 'The output should not be empty';

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
# CHECK : Check LogLevel /etc/ssh/sshd_config
# ------------------------------------------------------------------

step_cmd = 'grep -i "^\\s*LogLevel "' + log_level + ' /etc/ssh/sshd_config 2>/dev/null | grep -vE "^\\s*#"';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value){
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

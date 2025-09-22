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
  script_oid("1.3.6.1.4.1.25623.1.0.130313");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure a Proper Value for LoginGraceTime");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.17 Configure a Proper Value for LoginGraceTime (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.17 Configure a Proper Value for LoginGraceTime (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.17 Configure a Proper Value for LoginGraceTime (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.17 Configure a Proper Value for LoginGraceTime (Recommendation)");

  script_tag(name:"summary", value:"LoginGraceTime is used to limit the login time of a user. If a
user does not complete the login within the time specified by LoginGraceTime, the connection is
automatically disconnected. You are advised to set this field to a value less than or equal to 60,
in seconds.

If this field is set to a large value, attackers can use a large number of unfinished login
connections to consume server resources. As a result, administrators fail to log in to the system.
If the value is not explicitly configured in the configuration file, the system uses the default
value 120, in seconds.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure a Proper Value for LoginGraceTime";

solution = "Open the /etc/ssh/sshd_config file, set the LoginGraceTime field to the time limit (in
seconds), and restart the sshd service.

# vim /etc/ssh/sshd_config
LoginGraceTime 60
# systemctl restart sshd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# val=$(awk "/^LoginGraceTime/ {print \\$2}" /etc/ssh/sshd_config); if [ -z "$val" ]; then echo 120; else echo "$val"; fi';

expected_value = 'The output should less than or equal to "60"';

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
# CHECK : LoginGraceTime less than or equal 60
# ------------------------------------------------------------------

step_cmd = 'val=$(awk "/^LoginGraceTime/ {print \\$2}" /etc/ssh/sshd_config); if [ -z "$val" ]; then echo 120; else echo "$val"; fi';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(int(actual_value) <= int(60)){
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
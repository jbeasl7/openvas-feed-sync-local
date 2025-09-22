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
  script_oid("1.3.6.1.4.1.25623.1.0.130321");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure a Proper Number of Concurrent Sessions Allowed for a Single SSH Connection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.13 Configure a Proper Number of Concurrent Sessions Allowed for a Single SSH Connection (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.13 Configure a Proper Number of Concurrent Sessions Allowed for a Single SSH Connection (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.13 Configure a Proper Number of Concurrent Sessions Allowed for a Single SSH Connection (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.13 Configure a Proper Number of Concurrent Sessions Allowed for a Single SSH Connection (Recommendation)");

  script_tag(name:"summary", value:"SSH allows a client that supports multiplexing to establish
multiple sessions based on a network connection. MaxSessions limits the number of concurrent SSH
sessions that can be established for each network connection. This prevents system resources from
being occupied by a single connection or a few connections without limitation and prevents DoS
attacks. If MaxSessions is set to 1, session multiplexing is disabled. That is, only one session is
allowed for a connection. If MaxSessions is set to 0, all connection sessions are blocked.

By default, this is not configured in the configuration file in openEuler. The default value 10 is
used in the code. You are advised to configure the upper limit in the configuration file as
required.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure a Proper Number of Concurrent Sessions Allowed for a Single SSH Connection";

solution = "Open the /etc/ssh/sshd_config file, set the MaxSessions field to the maximum number of
allowed connection sessions, and restart the sshd service.

# vim /etc/ssh/sshd_config
MaxSessions 5
# systemctl restart sshd

Note: Suppose that MaxSessions is set to 5. After the configuration is modified and the service is
restarted, the existing SSH sessions are not counted. That is, 5 more sessions can be created in
the SSH channel. If the server is restarted after the configuration is modified, only 5 sessions
can exist in one channel.";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -i "^MaxSessions" /etc/ssh/sshd_config';

expected_value = 'The output should be equal to "MaxSessions 5"';

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
# CHECK : Verify command `grep -i "^MaxSessions" /etc/ssh/sshd_config`
# ------------------------------------------------------------------
step_cmd = 'grep -i "^\\s*MaxSessions" /etc/ssh/sshd_config 2>/dev/null';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == 'MaxSessions 5'){
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

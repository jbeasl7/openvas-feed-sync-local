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
  script_oid("1.3.6.1.4.1.25623.1.0.130312");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the Authentication Blocklist and Allowlist Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.22 Configure the Authentication Blocklist and Allowlist Properly (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.22 Configure the Authentication Blocklist and Allowlist Properly (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.22 Configure the Authentication Blocklist and Allowlist Properly (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.22 Configure the Authentication Blocklist and Allowlist Properly (Recommendation)");

  script_tag(name:"summary", value:"SSH provides the blocklist and allowlist function. You can set
a list of users or user groups to allow or deny SSH login for them. By default, this function is
not configured in openEuler. The related fields are as follows:

AllowUsers <userlist>

userlist specifies the space-separated users who are allowed to log in to the system. UIDs are not
supported. The value can be in the user@host format. user and host are checked separately to
prevent specific users from logging in to the system from specific hosts. Wildcards * and ? can be
used. After the configuration, unauthorized users are automatically denied to log in to the SSH
service.

AllowGroups <grouplist>

grouplist specifies the space-separated names of user groups that are allowed to log in to the
system. GIDs are not supported.

DenyUsers <userlist>

userlist specifies the space-separated users who are not allowed to log in to the system. UIDs are
not supported.

DenyGroups <grouplist>

grouplist specifies the space-separated names of user groups that are denied to log in to the
system. GIDs are not supported.

You are advised to delete unused users or user groups instead of using DenyUsers/DenyGroups to deny
their login requests. If a user is allowed or denied to log in to the system only on certain
clients, you can configure the Allow or Deny rule in the user@host format.

If both the Allow and Deny rules are configured, the union of the rules apply. That is, only users
or user groups in the Allow rule and outside the Deny rule are allowed to log in to the system.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure the Authentication Blocklist and Allowlist Properly";

solution = "Based on the actual business scenario, add relevant Allow or Deny fields to the
/etc/ssh/sshd_config file and restart the sshd service. For example:

<quote>bash
# vim /etc/ssh/sshd_config
AllowUsers root test
DenyUsers test1
# systemctl restart sshd
<quote>";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -E "^\\s*AllowUsers|^\\s*AllowGroups|^\\s*DenyUsers|^\\s*DenyGroups" /etc/ssh/sshd_config 2>/dev/null';

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
# CHECK : Check user config in /etc/ssh/sshd_config 2
# ------------------------------------------------------------------

step_cmd = 'grep -E "^\\s*AllowUsers|^\\s*AllowGroups|^\\s*DenyUsers|^\\s*DenyGroups" /etc/ssh/sshd_config 2>/dev/null';
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

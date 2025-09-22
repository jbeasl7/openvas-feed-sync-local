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
  script_oid("1.3.6.1.4.1.25623.1.0.130310");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure a Proper SSH Service Authentication Mode");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.2 Configure a Proper SSH Service Authentication Mode (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.2 Configure a Proper SSH Service Authentication Mode (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.2 Configure a Proper SSH Service Authentication Mode (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.2 Configure a Proper SSH Service Authentication Mode (Requirement)");

  script_tag(name:"summary", value:"A proper authentication mode helps ensure user and system data
security. Typically, the user/password authentication mode is suitable for human-machine users. In
non-interactive login scenarios, the public and private keys are suitable for authentication.
In high-risk scenarios, only the public and private keys can be used for authentication. If
host-based identity authentication is used, attackers can intrude the system without passwords
through DNS spoofing or IP spoofing.
The SSH service itself provides multiple authentication modes. However, for security purposes,
host-based identity authentication is prohibited.

By default, the user/password authentication mode is used in openEuler. During system installation,
the password of the root administrator must be configured.
openEuler supports public and private key authentication. openEuler supports interactive
user/password authentication. A correct authentication mode must be configured based on the service
scenario requirements.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure a Proper SSH Service Authentication Mode";

solution = "1. Enable user/password authentication.
Open the /etc/ssh/sshd_config file, enable PasswordAuthentication, and restart the sshd service.

# vim /etc/ssh/sshd_config
PasswordAuthentication yes
# systemctl restart sshd

2. Enable public and private key authentication.
Open the /etc/ssh/sshd_config file, enable PubkeyAuthentication, configure the public key storage
path, and restart the sshd service.

# vim /etc/ssh/sshd_config
PubkeyAuthentication yes
AuthorizedKeysFile      .ssh/authorized_keys
# systemctl restart sshd

Generate RSA public and private keys on the client and copy the public key to a specified
directory, for example, the .ssh/authorized_keys directory in the preceding example.

3. Enable interactive user/password authentication.
Open the /etc/ssh/sshd_config file, enable ChallengeResponseAuthentication, and restart the sshd
service.

# vim /etc/ssh/sshd_config
ChallengeResponseAuthentication yes
# systemctl restart sshd

4.Disable host-based authentication.";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -Ei "^PasswordAuthentication|^PubkeyAuthentication|^ChallengeResponseAuthentication|^IgnoreRhosts|^HostbasedAuthentication" /etc/ssh/sshd_config';

expected_value = 'The output should contain a "IgnoreRhosts yes" and contain "HostbasedAuthentication no" and the output should contains a least one "PasswordAuthentication yes" or "ChallengeResponseAuthentication yes" or "PubkeyAuthentication yes"';

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
# CHECK : SSH service authentication modes should be compliant
# ------------------------------------------------------------------

step_cmd = 'grep -Ei "^PasswordAuthentication|^PubkeyAuthentication|^ChallengeResponseAuthentication|^IgnoreRhosts|^HostbasedAuthentication" /etc/ssh/sshd_config';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if((strstr(actual_value, 'IgnoreRhosts yes') && strstr(actual_value, 'HostbasedAuthentication no')) && (strstr(actual_value, 'PasswordAuthentication yes') || strstr(actual_value, 'ChallengeResponseAuthentication yes') || strstr(actual_value, 'PubkeyAuthentication yes'))){
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
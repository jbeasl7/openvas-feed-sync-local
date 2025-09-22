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
  script_oid("1.3.6.1.4.1.25623.1.0.130322");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Configure the Encryption Algorithm Overwriting Policy for the SSH Service");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.8 Do Not Configure the Encryption Algorithm Overwriting Policy for the SSH Service (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.8 Do Not Configure the Encryption Algorithm Overwriting Policy for the SSH Service (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.8 Do Not Configure the Encryption Algorithm Overwriting Policy for the SSH Service (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.8 Do Not Configure the Encryption Algorithm Overwriting Policy for the SSH Service (Requirement)");

  script_tag(name:"summary", value:"The configuration files of the SSH encryption algorithms are
/etc/ssh/sshd_config and /etc/sysconfig/sshd. When the SSH service is running, you can edit the
/etc/sysconfig/sshd file to overwrite the encryption algorithm policy. If the encryption algorithm
overwriting policy is configured, users are allowed to configure low-security encryption
algorithms, message authentication algorithms, and key exchange algorithms, which reduces system
security. Attackers can exploit these insecure algorithms to crack system information, thus
increasing security risks.

By default, no encryption algorithm overwriting policy is configured in openEuler.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Configure the Encryption Algorithm Overwriting Policy for the SSH Service";

solution = "Edit the SSH service configuration file /etc/sysconfig/sshd to delete the encryption
algorithm policy or comment out the line, and reload the sshd configuration.

# vim /etc/sysconfig/sshd

Method 1: Delete the encryption algorithm policy.
CRYPTO_POLICY=
Method 2: Comment out the line.
# CRYPTO_POLICY='-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr -oMACS=hmac-sha2-512,hmac-sha2-256'

# systemctl reload sshd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep "^\\s*CRYPTO_POLICY=" /etc/sysconfig/sshd';

expected_value = 'The output should be empty';

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
# CHECK : Verify command `grep "^\s*CRYPTO_POLICY=" /etc/sysconfig/sshd`
# ------------------------------------------------------------------

step_cmd = 'grep "^\\s*CRYPTO_POLICY=" /etc/sysconfig/sshd';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(!actual_value){
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
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
  script_oid("1.3.6.1.4.1.25623.1.0.130327");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Proper Cryptographic Algorithms for the SSH Service");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.7 Configure Proper Cryptographic Algorithms for the SSH Service (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.7 Configure Proper Cryptographic Algorithms for the SSH Service (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.7 Configure Proper Cryptographic Algorithms for the SSH Service (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.7 Configure Proper Cryptographic Algorithms for the SSH Service (Requirement)");

  script_tag(name:"summary", value:"As cryptographic technologies develop and computing
capabilities improve, some cryptographic algorithms are no longer suitable for today's security
field. For example, the MD5 algorithm was cracked by the Professor Wang Xiaoyun and her team from
Shandong University in 2004 (by manually crafting two messages with the same MD5 value). In 2007,
Marc Stevens, a cryptographer, forged a digital certificate based on the previous cracking.
Therefore, the security of MD5 has been severely compromised and MD5 should not be used for all
cryptographic security purposes, including digital signature, HMAC, one-way protection of
passwords, key derivation, and random number generation (RNG). However, MD5 can be used for
non-cryptographic security purposes, such as the verification of line errors and bit flipping
caused by medium damages. For another example, the DES algorithm is prone to brute-force cracking
due to the development of cryptography analysis technologies and improvement of computing
capabilities. Existing brute-force cracking devices can reduce the time required for DES cracking
to less than one day. These algorithms are insecure cryptographic algorithms. If these insecure
cryptographic algorithms are still used, data risks may occur.

Strong cryptographic algorithms are those that are widely recognized by the industry, have
comparative advantages in security strength over other cryptographic algorithms in applicable
scenarios, and have provable security or against which the cracking computation is obviously
infeasible under reasonable security assumption.

Cryptographic algorithms are used to encrypt and decrypt data. If the configured algorithms are
insecure, security risks increase because weak algorithms have been or are about to be cracked in
the industry.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure Proper Cryptographic Algorithms for the SSH Service";

solution = "Open the /etc/ssh/sshd_config file, set the SSH cryptographic algorithms in the file,
and restart the sshd service to make the setting take effect. The following is an example. You need
to set the algorithms as required.

# vim /etc/ssh/sshd_config
Ciphers
aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@ope
nssh.com
# systemctl restart sshd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -i "^Ciphers" /etc/ssh/sshd_config';

expected_value = 'The output should contain any of these values:
  (Ciphers\\s*)?(aes128-ctr|aes192-ctr|aes256-ctr|aes128-gcm@openssh.com|aes256-gcm@openssh.com)';

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
# CHECK : Verify command `grep -i "^Ciphers" /etc/ssh/sshd_config`
# ------------------------------------------------------------------

step_cmd = 'grep -i "^Ciphers" /etc/ssh/sshd_config';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);
value_list = split(actual_value, sep: ",", keep:FALSE);

if(value_list){
  foreach value(value_list){
    if(value =~ '(Ciphers\\s*)?(aes128-ctr|aes192-ctr|aes256-ctr|aes128-gcm@openssh.com|aes256-gcm@openssh.com)'){
      compliant = "yes";
      comment = "Check passed";
    } else {
      compliant = "no";
      comment = "Check failed";
      break;
    }
  }
} else {
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
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
  script_oid("1.3.6.1.4.1.25623.1.0.130449");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That GPG Verification Is Configured for the Yum Repositories");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.6 Ensure That GPG Verification Is Configured for the Yum Repositories (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.6 Ensure That GPG Verification Is Configured for the Yum Repositories (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.6 Ensure That GPG Verification Is Configured for the Yum Repositories (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.6 Ensure That GPG Verification Is Configured for the Yum Repositories (Requirement)");

  script_tag(name:"summary", value:"Software packages may be tampered with by attackers during
network transmission or local storage. If the integrity verification is not performed on the
software packages, software tampered with by attackers may be installed. As a result, the server or
even the entire network cluster is attacked. If a repository is used to install and upgrade OS
software, GPG verification must be configured.

openEuler allows you to run the dnf or yum command to download, install, or upgrade RPM packages
from repositories. You can configure repositories using files in the /etc/yum.repo.d directory. GPG
verification must be configured and the GPG public key must be installed in the system.
Alternatively, specify the public key download address in the repository configuration files.

GPG public keys are the key to verifying the validity of RPM packages. Ensure that a trusted GPG
public key is installed.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That GPG Verification Is Configured for the Yum Repositories";

solution = 'All commercial RPM packages of openEuler are signed by a GPG private key. When you run
the rpm command to install a package, the system checks whether the signature is valid. If the
verification fails, the package can be installed, but an alarm is displayed as follows. Do not skip
signature and integrity verification by using the --nosignature or --nodigest option.

# rpm -ivh keyutils-<version numbers>.rpm
warning: keyutils-<version numbers>.rpm: Header V4 RSA/SHA256 Signature, key ID e2ec75bc: NOKEY
Verifying.            ################################# [100%]
Preparing.            ################################# [100%]
Updating / installing.
   1:keyutils-<version numbers>  ################################# [100%]

To use a repository to install RPM packages, you must add gpgcheck=1 to the repository
configuration file to enable GPG verification and add the correct address for downloading the GPG
public key.

# vim /etc/yum.repos.d/base.repo
[Euler]
name=Euler
baseurl=<repository address>
gpgkey=<repository GPG public key address>
enabled=1
priority=1
gpgcheck=1

If the repository configuration file does not contain the address for downloading the GPG public
key, you must run the rpm command to install the public key of the corresponding repository. If
there are multiple repositories, each repository may have a different GPG public key. In this case,
you need to install the GPG public keys separately.

# rpm --import ./key';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# rpm -qa gpg-pubkey*

2. Run the command in the terminal:
# grep -inEh "^\\s*gpgcheck" /etc/yum.repos.d/* 2>/dev/null | grep -v -x -i ".*gpgcheck=1"';

expected_value = '1. The output should not be empty
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
# CHECK 1 :  Check gpg-pubkey package is installed or not
# ------------------------------------------------------------------

step_cmd_check_1 = 'rpm -qa gpg-pubkey*';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check in the /etc/yum.repos.d
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -inEh "^\\s*gpgcheck" /etc/yum.repos.d/* 2>/dev/null | grep -v -x -i ".*gpgcheck=1"';
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134204");
  script_version("2026-08-05T06:26:26+0000");
  script_tag(name:"last_modification", value:"2026-08-05 06:26:26 +0000 (Wed, 05 Aug 2026)");
  script_tag(name:"creation_date", value:"2026-07-29 08:00:09 +0000 (Wed, 29 Jul 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure GPG Public Key Is Configured");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "compliance_os_check.nasl");
  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/hce");
  script_xref(name:"Policy", value:"Huawei Cloud HCE 2.0 Security Configuration Baseline: 1.3.1 Ensure GPG Public Key Is Configured (Required)(Automated)");

  script_tag(name:"summary", value:"OS software vendors usually use the GPG private key
  to sign RPM packages and release the GPG public key. The GPG public key is usually contained
  in the ISO file or the Repo source on the official website.
  The RPM package manager can verify the integrity of RPM software packages using the GPG
  public key. Importing the GPG public key can verify whether a software package is from a
  valid vendor, preventing the installation of the malware from endangering system security.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure GPG Public Key Is Configured";

solution = "Download the GPG public key file from the official website of the software vendor
and complete the configuration.
# yum install hce-gpg-keys
# rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-HCE-2";

check_type = "SSH_Cmd";

action = "Run the command in the terminal:
# rpm -q gpg-pubkey*";

expected_value = "The output should list an installed gpg-pubkey package.";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

step_cmd = "rpm -qa gpg-pubkey*";
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(eregmatch(string: actual_value, pattern:"(Permission denied|Command not found|Segmentation fault|syntax error)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(actual_value && !eregmatch(string: actual_value, pattern:"not installed", icase: TRUE)){
  compliant = "yes";
  comment = "Check passed";
}else{
  compliant = "no";
  comment = "Check failed";
}

target = get_kb_item("policy/ssh/login/os-release");
comment = "Target: " + target + "\n" + comment;

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);

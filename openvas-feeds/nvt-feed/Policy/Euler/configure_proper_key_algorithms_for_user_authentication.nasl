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
  script_oid("1.3.6.1.4.1.25623.1.0.130325");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Proper Key Algorithms for User Authentication");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.4 Configure Proper Key Algorithms for User Authentication (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.4 Configure Proper Key Algorithms for User Authentication (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.4 Configure Proper Key Algorithms for User Authentication (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.4 Configure Proper Key Algorithms for User Authentication (Requirement)");

  script_tag(name:"summary", value:"If the public and private key authentication mode is used, the
public and private key algorithms on the client must be restricted to avoid using insecure
algorithms that have been phased out in the industry.

The recommended security algorithms are sorted by priority as follows. The algorithms have been
configured by default in openEuler.

ssh-ed25519

ssh-ed25519-cert-v01@openssh.com

rsa-sha2-256

rsa-sha2-512

The ssh-rsa public key algorithm defined in RFC 4253 uses SHA1 for hash calculation. Therefore,
this algorithm cannot be used.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure Proper Key Algorithms for User Authentication";

solution = "Modify the algorithm list in the PubkeyAcceptedKeyTypes field in the
/etc/ssh/sshd_config file, and restart the sshd service. Use commas (,) to separate different
algorithms.

# vim /etc/ssh/sshd_config
PubkeyAcceptedKeyTypes ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512
# systemctl restart sshd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep "^PubkeyAcceptedKeyTypes" /etc/ssh/sshd_config';

expected_value = 'The output should contain any of these values:
  (PubkeyAcceptedKeyTypes\\s*)?(ssh-ed25519|ssh-ed25519-cert-v01@openssh.com|rsa-sha2-256|rsa-sha2-512)';

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
# CHECK : Verify command `grep "^PubkeyAcceptedKeyTypes" /etc/ssh/sshd_config`
# ------------------------------------------------------------------

step_cmd = 'grep "^PubkeyAcceptedKeyTypes" /etc/ssh/sshd_config';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);
value_list = split(actual_value, sep: ",", keep:FALSE);

if(value_list){
  foreach value(value_list){
    if(value =~ '(PubkeyAcceptedKeyTypes\\s*)?(ssh-ed25519|ssh-ed25519-cert-v01@openssh.com|rsa-sha2-256|rsa-sha2-512)'){
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
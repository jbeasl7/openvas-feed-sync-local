# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130314");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Use X11 Forwarding");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.14 Do Not Use X11 Forwarding (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.14 Do Not Use X11 Forwarding (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.14 Do Not Use X11 Forwarding (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.14 Do Not Use X11 Forwarding (Requirement)");

  script_tag(name:"summary", value:"The X11 forwarding function of SSH allows the GUI program of
the remote host to be executed on the local host. If the X11 forwarding function is enabled, the
attack surface is expanded and other users on the X11 server may attack the local host. If the
function is not required in the service scenario, it must be disabled.

By default, the X11 forwarding function is disabled in openEuler.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Use X11 Forwarding";

solution = "Open the /etc/ssh/sshd_config file, set the X11Forwarding field to no, and restart the
sshd service.

# vim /etc/ssh/sshd_config
X11Forwarding no
# systemctl restart sshd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal :
# grep -i "^X11Forwarding" /etc/ssh/sshd_config';

expected_value ='The output should be equal to "X11Forwarding no"';

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
# CHECK : Verify command `grep -i "^X11Forwarding" /etc/ssh/sshd_config`
# ------------------------------------------------------------------

step_cmd = 'grep -i "^X11Forwarding" /etc/ssh/sshd_config';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == 'X11Forwarding no'){
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

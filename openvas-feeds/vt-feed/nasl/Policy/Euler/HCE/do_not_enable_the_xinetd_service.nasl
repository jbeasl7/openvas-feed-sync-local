# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134061");
  script_version("2026-08-05T06:26:26+0000");
  script_tag(name:"last_modification", value:"2026-08-05 06:26:26 +0000 (Wed, 05 Aug 2026)");
  script_tag(name:"creation_date", value:"2026-07-17 00:00:00 +0000 (Fri, 17 Jul 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Enable the xinetd Service");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "compliance_os_check.nasl");
  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/hce");
  script_xref(name:"Policy", value:"Huawei Cloud HCE 2.0 Security Configuration Baseline: 1.2.18 Do Not Enable xinetd Service (Required)(Automated)");

  script_tag(name:"summary", value:"Extended Internet Services Daemon (xinetd) is a super service
  daemon that manages and controls network services. It runs on many Unix-like systems and manages
  Internet-based connections. It can start and stop various network services (such as FTP, Telnet,
  and HTTP) and provide some additional functions. It offers a more secure alternative to the older
  inetd (the Internet daemon). However, it has been deprecated in most modern Linux distributions.
  Therefore, xinetd and the services hosted by it should be disabled. xinetd is disabled by default
  in HCE.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Enable the xinetd Service";

solution = "Run the following commands to disable xinetd:
# systemctl --now disable xinetd
# systemctl --now stop xinetd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# systemctl is-enabled xinetd';

expected_value = 'The output should be equal to "disabled" or "not-found", or contain "Failed to get unit file state".';

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

step_cmd = 'systemctl is-enabled xinetd';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(actual_value == 'disabled' || actual_value == 'not-found' || strstr(actual_value, 'Failed to get unit file state')){
  compliant = "yes";
  comment = "The xinetd service is disabled or not installed.";
}else{
  compliant = "no";
  comment = "The xinetd service is enabled.";
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

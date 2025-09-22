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
  script_oid("1.3.6.1.4.1.25623.1.0.130328");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Kernel Parameter kptr_restrict Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.3 Configure Kernel Parameter kptr_restrict Properly (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.3 Configure Kernel Parameter kptr_restrict Properly (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.3 Configure Kernel Parameter kptr_restrict Properly (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.3 Configure Kernel Parameter kptr_restrict Properly (Requirement)");

  script_tag(name:"summary", value:"kptr_restrict is used to protect kernel symbol addresses. When
the protection level is low, common users can obtain kernel symbol addresses, which are easy to be
exploited by attackers. This increases the attack surface and reduces system security.

Currently, kptr_restrict can be set to any of the following values:

0 = Both common users and users with the CAP_SYSLOG privilege have the read permission (the read
address is the hash value of the kernel symbol address).

1 = Only users with the CAP_SYSLOG privilege have the read permission (the read address is the
actual address of the kernel symbol). After a common user reads the address, the kernel symbol
address is printed as all 0s.

2 = Common users and users with the CAP_SYSLOG privilege do not have the read permission. The read
kernel symbol address is displayed as all 0s.

To facilitate maintenance and fault locating, kptr_restrict is set to 0 by default in openEuler.
You can set this parameter as required.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure Kernel Parameter kptr_restrict Properly";

solution = "You are advised to set kptr_restrict to 1 by running the following command:

# echo 1 > /proc/sys/kernel/kptr_restrict

Alternatively, open the /etc/sysctl.conf file, add or modify the configuration, and run the sysctl
-p /etc/sysctl.conf command.

kernel.kptr_restrict=1";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# sysctl kernel.kptr_restrict';

expected_value = 'The output should be equal to "kernel.kptr_restrict = 1"';

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
# CHECK : Verify command `sysctl kernel.kptr_restrict`
# ------------------------------------------------------------------

step_cmd = 'sysctl kernel.kptr_restrict';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == 'kernel.kptr_restrict = 1'){
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
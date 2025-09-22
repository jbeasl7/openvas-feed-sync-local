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
  script_oid("1.3.6.1.4.1.25623.1.0.130293");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Enable auditd to Start upon System Startup");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.8 Enable auditd to Start upon System Startup (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.8 Enable auditd to Start upon System Startup (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.8 Enable auditd to Start upon System Startup (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.8 Enable auditd to Start upon System Startup (Recommendation)");

  script_tag(name:"summary", value:"By enabling auditd to start upon system startup, you can audit
the events generated during system startup before the auditd service is started. If audit is not
enabled during system startup, you may not be able to audit attacks during the startup procedure.

By default, audit is not enabled during system startup in openEuler. You are advised to determine
whether to add audit=1 to kernel boot parameters based on the actual scenario so that audit can be
enabled during system startup.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Enable auditd to Start upon System Startup";

solution = "1. Open the grub.cfg file and add the configuration to the end of the corresponding
kernel boot parameter. Note that the directory where the grub.cfg file is located varies according
to the system installation configuration. In most cases, the file exists in the /boot/grub2/ or
/boot/efi/EFI/openeuler/ directory.

# vim /boot/efi/EFI/openeuler/grub.cfg
linuxefi /vmlinuz-<kernel version> root=/dev/mapper/openeuler-root ro
resume=/dev/mapper/openeuler-swap rd.lvm.lv=openeuler/root rd.lvm.lv=openeuler/swap
crashkernel=512M quiet audit=1

2. Alternatively, modify the /etc/default/grub configuration file, add audit=1 to the
GRUB_CMDLINE_LINUX field, and regenerate the grub.cfg file.

# vim /etc/default/grub
GRUB_CMDLINE_LINUX=<quote>/dev/mapper/openeuler-swap rd.lvm=openeuler/root rd.lvm.lv=openeuler/swap
crashkernel quiet audit=1<quote>

# grub2-mkconfig -o /boot/grub2/grub.cfg

3. Restart the system for the modification to take effect.
# reboot";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# cat /proc/cmdline | grep "audit=1"';

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
# CHECK : Verify command `cat /proc/cmdline | grep "audit=1"`
# ------------------------------------------------------------------

step_cmd = 'cat /proc/cmdline | grep "audit=1"';
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
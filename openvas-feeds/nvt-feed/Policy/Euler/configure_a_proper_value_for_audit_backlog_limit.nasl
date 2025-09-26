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
  script_oid("1.3.6.1.4.1.25623.1.0.130289");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure a Proper Value for audit_backlog_limit");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.9 Configure a Proper Value for audit_backlog_limit (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.9 Configure a Proper Value for audit_backlog_limit (Recommendation)");

  script_tag(name:"summary", value:"audit_backlog_limit sets the buffer queue length for audit
events awaiting transfer to the audit service. The default value is 64. If the queue is full, audit
events are discarded and an alarm log is generated, indicating that the queue is full. If the value
is too small, audit events may be lost.

If auditd is enabled during system startup, you are advised to set audit_backlog_limit to a large
value. This is because the auditd service has not started during kernel startup, and all events are
buffered in the queue.

The value of audit_backlog_limit is not configured in openEuler by default. You are advised to
configure the value based on the actual scenario.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Configure a Proper Value for audit_backlog_limit";

solution = "1. Open the grub.cfg file and add the configuration to the end of the corresponding
kernel boot parameter. Note that the directory where the grub.cfg file is located varies according
to the system installation configuration. In most cases, the file exists in the /boot/grub2/ or
/boot/efi/EFI/openeuler/ directory.

# vim /boot/grub2/grub.cfg
linuxefi /vmlinuz-<kernel version> root=/dev/mapper/openeuler-root ro
resume=/dev/mapper/openeuler-swap rd.lvm.lv=openeuler/root rd.lvm.lv=openeuler/swap
crashkernel=512M quiet audit=1 audit_backlog_limit=<size>

2. Alternatively, modify the /etc/default/grub configuration file, add audit_backlog_limit=<size>
to the GRUB_CMDLINE_LINUX field, and regenerate the grub.cfg file.

# /etc/default/grub
GRUB_CMDLINE_LINUX=<quote>/dev/mapper/openeuler-swap rd.lvm=openeuler/root rd.lvm.lv=openeuler/swap
crashkernel quiet audit=1 audit_backlog_limit=<size><quote>

# grub2-mkconfig -o /boot/grub2/grub.cfg

3. Restart the system for the modification to take effect.

# reboot";

check_type = "Manual";

action = "Needs manual check";

expected_value = script_get_preference("Status", id:1);

actual_value = expected_value;

# ------------------------------------------------------------------
# MANUAL CHECK
# ------------------------------------------------------------------

if(expected_value == "Compliant"){
  compliant = "yes";
  comment = "Marked as Compliant via Policy";
}
else if(expected_value == "Not Compliant"){
  compliant = "no";
  comment = "Marked as Non-Compliant via Policy.";
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

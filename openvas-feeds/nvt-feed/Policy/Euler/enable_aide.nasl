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
  script_oid("1.3.6.1.4.1.25623.1.0.130391");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Enable AIDE");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.2 Enable AIDE (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.2 Enable AIDE (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.2 Enable AIDE (Recommendation)");

  script_tag(name:"summary", value:"Advanced intrusion detection environment (AIDE) is an intrusion
detection tool that checks the integrity of system files and directories and identifies those
maliciously tampered with. In principle, the integrity check can be performed only after an AIDE
benchmark database is constructed, which contains some attributes of files or directories, such as
permissions and users. The system compares the current system status with the benchmark database to
obtain the integrity check result, and then reports the check report recording the file or
directory changes of the current system.
With AIDE enabled, the system can effectively identify malicious file or directory tampering,
improving system integrity and security. The files or directories to be checked can be configured
flexibly. You only need to query the check report to determine whether malicious tampering occurs.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Enable AIDE";

solution = "1. If AIDE is not installed, run the yum or dnf command to install the software
package.

yum install aide
Or
dnf install aide

2. Configure the files or directories to be monitored in the /etc/aide.conf configuration file. By
default, some directories to be monitored are configured in the /etc/aide.conf file, including
important directories such as /boot, /bin, /lib, and /lib64. Add files or directories to be
monitored as required.

# vim /etc/aide.conf
/boot   NORMAL
/bin    NORMAL
/lib    NORMAL
/lib64  NORMAL
<add new folders>

3. Generate the benchmark database. After the initialization command is executed, the
aide.db.new.gz file is generated in the /var/lib/aide directory. Rename the file as aide.db.gz,
which is the benchmark database.

# aide --init
# mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
4. Run the following aide --check<semicolon> command to perform the intrusion check. The check
result is displayed on the screen and saved to the /var/log/aide/aide.log file.

# aide --check

5. Update the benchmark database.

# aide --update
# mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz";

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

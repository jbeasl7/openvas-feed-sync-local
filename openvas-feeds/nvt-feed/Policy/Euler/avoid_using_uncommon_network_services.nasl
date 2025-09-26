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
  script_oid("1.3.6.1.4.1.25623.1.0.130371");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:21 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Avoid Using Uncommon Network Services");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.1 Avoid Using Uncommon Network Services (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.1 Avoid Using Uncommon Network Services (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.1 Avoid Using Uncommon Network Services (Recommendation)");

  script_tag(name:"summary", value:"Some protocols are seldom used and their communities develop
slowly. Therefore, related security issues cannot be quickly resolved. If these protocols are not
disabled, attackers may exploit the protocols or code vulnerabilities to launch attacks.

Stream Control Transmission Protocol (SCTP) is used to transmit multiple data streams between two
ends of a network connection simultaneously. SCTP provides services similar to UDP and TCP.

Transparent Inter-process Communication (TIPC) is used for inter-process communication. It was
originally specially designed for inter-cluster communication. It allows designers to create an
application that can quickly and reliably communicate with other applications without considering
their locations in the cluster environment.

If services such as SCTP and TIPC are not required in service scenarios, disable them in the kernel
to reduce attack scenarios.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Avoid Using Uncommon Network Services";

solution = "In the /etc/modprobe.d/ directory, add a configuration file with a random file name
and the .conf extension, set its owner and owner group to root, and set its permissions to 600.
Enter the following content to disable the SCTP and TIPC protocols:

# vim /etc/modprobe.d/test.conf
install sctp /bin/true
install tipc /bin/true";

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

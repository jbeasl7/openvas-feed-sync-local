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
  script_oid("1.3.6.1.4.1.25623.1.0.130364");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Bind Network Interfaces to the Correct Zones");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.3 Bind Network Interfaces to the Correct Zones (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.3 Bind Network Interfaces to the Correct Zones (Recommendation)");

  script_tag(name:"summary", value:"Different filtering policies can be configured for different
firewall zones. If the server network is complex and has multiple interfaces that provide different
service functions, it is recommended that interfaces be configured in different zones and different
firewall policies be configured. For example, SSH access is not allowed for external service
interfaces, but the intranet management interface can be accessed through SSH. If all interfaces
are configured in the same zone, varying firewall policies cannot be configured for different
interfaces, which increases the management complexity and reduces the filtering efficiency of
firewall security protection. Due to incorrect configurations, packets that should be rejected may
be received.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Bind Network Interfaces to the Correct Zones";

solution = "Run the firewall-cmd command to remove an interface from a specified zone.

# firewall-cmd --zone=work --remove-interface eth1
success
Run the firewall-cmd command to add an interface to a specified zone.

# firewall-cmd --zone=work --add-interface eth1
success
Run the firewall-cmd command to add the current firewall configuration to the configuration file so
that the configuration takes effect permanently.

# firewall-cmd --runtime-to-permanent
success";

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

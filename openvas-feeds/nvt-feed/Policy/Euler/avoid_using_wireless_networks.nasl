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
  script_oid("1.3.6.1.4.1.25623.1.0.130370");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:21 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Avoid Using Wireless Networks");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.2 Avoid Using Wireless Networks (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.2 Avoid Using Wireless Networks (Recommendation)");

  script_tag(name:"summary", value:"If the hardware device contains wireless modules such as Wi-Fi
and Wi-Fi is enabled in the system, the server may connect to the network wirelessly. If the
connection is not managed, the network may be unstable and the attack surface increases.

If no wireless network is used, you are advised to disable the wireless network function as
required.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Avoid Using Wireless Networks";

solution = "Run the nmcli command to permanently disable Wi-Fi and WWAN. They remain disabled even
if the system is restarted.

# nmcli radio all off
# nmcli radio all
WIFI-HW  WIFI     WWAN-HW  WWAN
enabled  disabled  enabled  disabled";

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

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
  script_oid("1.3.6.1.4.1.25623.1.0.130359");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Proper Policies for INPUT of iptables");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.8 Configure Proper Policies for INPUT of iptables (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.8 Configure Proper Policies for INPUT of iptables (Recommendation)");

  script_tag(name:"summary", value:"The INPUT chain is used to filter packets received from
external systems. For any service provided for external systems, configure the corresponding INPUT
policy and enable the related port so that external clients can access the service through the port.

If the policy is not set, all packets that attempt to access related services are discarded because
the default policy is DROP.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Configure Proper Policies for INPUT of iptables";

solution = "Run the following command to add the ACCEPT policy to the INPUT chain:

# iptables -A INPUT -p <protocol> -s <source ip> -d <dest ip> --dport <dest port> -j ACCEPT

Example:
# iptables -A INPUT -p tcp --dport 22 -j ACCEPT

Run the following command to make the configured policy take effect permanently:

# service iptables save
iptables: Saving firewall rules to /etc/sysconfig/iptables: [  OK  ]

Run the following command to configure the IPv6-based policy:

# ip6tables -A INPUT -p <protocol> -s <source ip> -d <dest ip> --dport <dest port> -j ACCEPT

Example:
# ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT

Run the following command to make the configured policy take effect permanently:

# service ip6tables save
ip6tables: Saving firewall rules to /etc/sysconfig/ip6tables: [  OK  ]";

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

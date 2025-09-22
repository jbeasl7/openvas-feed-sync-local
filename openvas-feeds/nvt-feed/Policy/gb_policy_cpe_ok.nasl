# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103963");
  script_version("2022-07-26T10:10:42+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2014-01-06 11:42:20 +0700 (Mon, 06 Jan 2014)");
  script_name("CPE-based Policy Check OK");
  # nb: Needs to be in ACT_END because cpe_inventory.nasl is also there
  script_category(ACT_END);
  script_family("Policy");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("Policy/gb_policy_cpe.nasl", "compliance_tests.nasl");
  script_mandatory_keys("policy/cpe/checkfor");

  script_tag(name:"summary", value:"Shows all CPEs which are either present or missing (depending on
  what to check for) from CPE-based Policy Check.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("policy_functions.inc");

checkfor = get_kb_item("policy/cpe/checkfor");

if (checkfor == "present") {
  present = get_kb_item("policy/cpe/present");
  poss_present = get_kb_item("policy/cpe/possibly_present");

  if (present) {
    report = string("The following CPEs have been detected on the remote host\n\nPolicy-CPE|Detected-CPE\n");
    report += present;
  }

  if (poss_present) {
    report += string("\nThe following CPEs *may* have been detected on the remote host\n\nPolicy-CPE|Detected-CPE\n");
    report += poss_present;
  }
} else {
  missing = get_kb_item("policy/cpe/missing");

  if (missing) {
    report = string("The following CPEs are missing on the remote Host\n\n");
    report += missing;
  }
}

if (report) {
  # nb: If the Test should run as Policy, then report in Policy format
  if (get_kb_item("Compliance/verbose")) {
    default = "N/A";
    compliant = "Yes";
    fixtext = "None";
    type = "CPE Check";
    test = "Check detected CPEs on the host against the provided information.";
    info = ""; # nb: to make linter happy

    policy_reporting(result:report, default:default, compliant:compliant, fixtext:fixtext, type:type,
                     test:test, info:info);
  } else {
    log_message(port:0, data:report);
  }
}

exit(0);

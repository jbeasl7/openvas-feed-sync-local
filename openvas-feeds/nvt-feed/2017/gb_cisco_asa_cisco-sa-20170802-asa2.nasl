# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140271");
  script_version("2022-02-24T08:32:00+0000");
  script_tag(name:"last_modification", value:"2022-02-24 08:32:00 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2017-08-03 10:07:33 +0700 (Thu, 03 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-6752");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Adaptive Security Appliance Username Enumeration Information Disclosure Vulnerability (cisco-sa-20170802-asa2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"A vulnerability in the web interface of the Cisco Adaptive
  Security Appliance (ASA) could allow an unauthenticated, remote attacker to determine valid
  usernames. The attacker could use this information to conduct additional reconnaissance attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the interaction between Lightweight
  Directory Access Protocol (LDAP) and SSL Connection Profile when they are configured together. An
  attacker could exploit the vulnerability by performing a username enumeration attack to the IP
  address of the device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to determine valid usernames.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-asa2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

check_vers = ereg_replace(pattern: "(\(|\))", string: version, replace: ".");
check_vers = ereg_replace(pattern: "\.$", string: check_vers, replace: "");

affected = make_list(
  "9.3.3",
  "9.6.2");

foreach af (affected) {
  if (check_vers == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

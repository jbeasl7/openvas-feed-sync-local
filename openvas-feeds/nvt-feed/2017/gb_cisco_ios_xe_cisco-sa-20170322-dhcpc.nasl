# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106684");
  script_cve_id("CVE-2017-3864");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco IOS XE Software DHCP Client Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-dhcpc");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the DHCP client implementation of Cisco IOS XE Software
could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability occurs during the parsing of a crafted DHCP packet. An
attacker could exploit this vulnerability by sending crafted DHCP packets to an affected device that is
configured as a DHCP client.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause a reload of an
affected device, resulting in a DoS condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-04 16:49:00 +0000 (Fri, 04 Sep 2020)");
  script_tag(name:"creation_date", value:"2017-03-23 09:25:06 +0700 (Thu, 23 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

affected = make_list(
  '3.3.0SE',
  '3.3.0XO',
  '3.3.1SE',
  '3.3.1XO',
  '3.3.2SE',
  '3.3.2XO',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.6.0E',
  '3.6.1E',
  '3.6.2E',
  '3.6.2a.E',
  '3.6.3E',
  '3.6.4E',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

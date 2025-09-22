# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106584");
  script_cve_id("CVE-2017-3812");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Industrial Ethernet 2000 Series Switches CIP Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170201-psc1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the implementation of Common Industrial Protocol (CIP)
functionality in Cisco Industrial Ethernet 2000 Series Switches could allow an unauthenticated, remote attacker
to cause a denial of service (DoS) condition due to a system memory leak.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of malformed CIP packets. An
attacker could exploit this vulnerability by sending malformed CIP requests to a targeted device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause a DoS condition on
the targeted device due to low system memory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-02-09 16:05:18 +0700 (Thu, 09 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version", "cisco_ios/image");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco_ios/image");
if (!model || model !~ "^IE2000")
  exit(99);

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if (version == "15.2(5.4.32i)E2") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

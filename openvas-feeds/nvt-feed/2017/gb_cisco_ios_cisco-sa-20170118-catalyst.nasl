# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106523");
  script_cve_id("CVE-2017-3803");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco IOS for Catalyst 2960X and 3750X Switches Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-catalyst");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Cisco IOS Software forwarding queue of Cisco 2960X
and 3750X switches could allow an unauthenticated, adjacent attacker to cause a memory leak in the software
forwarding queue that would eventually lead to a partial denial of service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to improper processing of IPv6 Neighbor Discovery
(ND) packets. An attacker could exploit this vulnerability by sending a number of IPv6 ND packets to be processed
by an affected device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a memory leak in the software
forwarding queue that would eventually lead to a partial DoS service condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-01-19 09:15:35 +0700 (Thu, 19 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version", "cisco_ios/image");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

image = get_kb_item("cisco_ios/image");

if (!image || (image !~ "^C2960X" && image !~ "^C3750X"))
  exit(99);

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list( '15.2(2)E3',
                      '15.2(4)E1' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver( installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );


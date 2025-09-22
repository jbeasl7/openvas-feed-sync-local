# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106334");
  script_cve_id("CVE-2016-6434");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Firepower Management Center Console Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-ftmc1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"A vulnerability in the web console of Cisco Firepower Management Center
  could allow an authenticated, local attacker to bypass authentication and access sensitive information.");

  script_tag(name:"insight", value:"The vulnerability is due to the use of static credentials by the database
  on an affected system.");

  script_tag(name:"impact", value:"An authenticated user who can access the command-line interface (CLI) for an
  affected system may be able to leverage this vulnerability to access information in the database directly from a
  local shell.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-10-06 11:03:55 +0700 (Thu, 06 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_firepower_management_center_consolidation.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version == '6.0.1' ) {
  report = report_fixed_ver(  installed_version:version, fixed_version: "None Available" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

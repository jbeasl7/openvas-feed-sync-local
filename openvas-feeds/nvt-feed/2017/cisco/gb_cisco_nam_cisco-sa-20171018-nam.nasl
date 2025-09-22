# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113053");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-11-17 15:49:00 +0100 (Fri, 17 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-12285");

  script_name("Cisco Network Analysis Module Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_nam_consolidation.nasl");
  script_mandatory_keys("cisco/nam/detected");

  script_tag(name:"summary", value:"Cisco Prime NAM is prone to a directory traversal attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow the attacker to delete arbitrary files on the target host.");

  script_tag(name:"affected", value:"Cisco Prime Network Analysis Module through version 6.3");

  script_tag(name:"solution", value:"Update to 6.2(1b)P4 or 6.3(2) respectively.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171018-nam");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101527");

  exit(0);
}

CPE = "cpe:/a:cisco:prime_network_analysis_module";

include( "version_func.inc" );
include( "host_details.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

patch = get_kb_item( "cisco/nam/patch" );

if( version_is_less_equal( version: version, test_version: "6.2.1b" ) ) {
  if( version == "6.2.1b" && patch && patch >= 4 )
    exit( 99 );

  report = report_fixed_ver( installed_version: version, fixed_version: "6.2(1b)P4" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.3.0", test_version2: "6.3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.3(2)" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

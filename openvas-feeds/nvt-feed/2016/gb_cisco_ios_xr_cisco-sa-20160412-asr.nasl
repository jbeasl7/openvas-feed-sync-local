# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105646");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-05-04 17:40:34 +0200 (Wed, 04 May 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:20:00 +0000 (Sat, 03 Dec 2016)");

  script_cve_id("CVE-2016-1376");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco IOS XR for Cisco ASR 9000 Series Aggregation Services Routers Interface Flap Vulnerability (cisco-sa-20160412-asr)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ios_xr_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xr/detected", "cisco/ios_xr/model");

  script_tag(name:"summary", value:"A vulnerability in packet processing functions of Cisco IOS XR
  Software running on Cisco ASR 9000 Series Aggregation Services Routers could allow an
  unauthenticated, remote attacker to cause cyclic redundancy check (CRC) and symbol errors on the
  receiving interface of an affected device, which may lead to an interface flap.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper processing of packets that
  contain certain crafted bit patterns. An attacker could exploit this vulnerability by sending
  crafted packets to be processed by a line card of an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause CRC and
  symbol errors on the receiving interface of the device, which may lead to an interface flap.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160412-asr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! model = get_kb_item( "cisco/ios_xr/model" ) )
  exit( 0 );

if( "ASR9K" >!< model )
  exit( 99 );

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

affected = make_list( "4.2.3", "4.3.0", "4.3.2", "4.3.4", "5.3.1" );

foreach af ( affected ) {
  if( version == af ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"See vendor advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

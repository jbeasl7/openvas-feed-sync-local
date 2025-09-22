# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kamailio:kamailio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105592");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-03-31 14:51:12 +0200 (Thu, 31 Mar 2016)");

  script_cve_id("CVE-2016-2385");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Kamailio < 4.3.5 SEAS module encode_msg Heap Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_kamailio_sip_detect.nasl");
  script_mandatory_keys("kamailio/detected");

  script_tag(name:"summary", value:"Kamailio is prone to a heap buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The heap overflow can be triggered if Kamailio is configured to
  use the SEAS module.");

  script_tag(name:"impact", value:"An attacker may exploit this issue to cause a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Kamailio version prior to 4.3.5 with an enabled SEAS module.");

  script_tag(name:"solution", value:"Update to version 4.3.5 or later.");

  script_xref(name:"URL", value:"https://census-labs.com/news/2016/03/30/kamailio-seas-heap-overflow/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"4.3.5" ) ) {
  report = report_fixed_ver(  installed_version:version, fixed_version:"4.3.5" );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );

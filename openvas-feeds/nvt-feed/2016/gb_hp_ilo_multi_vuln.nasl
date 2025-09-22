# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106182");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-18 10:47:20 +0700 (Thu, 18 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:17:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2016-4375");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Integrated Lights-Out (iLO) Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("ilo_detect.nasl");
  script_mandatory_keys("hp/ilo/detected");

  script_tag(name:"summary", value:"HP Integrated Lights-Out (iLO) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Potential security vulnerabilities have been identified in HPE
  Integrated Lights Out. The vulnerabilities could lead to multiple remote vulnerabilities.");

  script_tag(name:"affected", value:"HPE Integrated Lights-Out 3 (iLO 3), Firmware for ProLiant G7 Servers
  prior to v1.88 and HPE Integrated Lights-Out 4 (iLO 4), prior to v2.44.");

  script_tag(name:"solution", value:"HPE has provided firmware updates to resolve this vulnerability. iLO 3
  version v1.88 or subsequent, iLO 4 version v2.44 or subsequent.");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05236950");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:hp:integrated_lights-out_3_firmware", "cpe:/o:hp:integrated_lights-out_4_firmware" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! version = get_app_version( cpe:cpe, port:port, nofork:TRUE ) )
  exit( 0 );

if( cpe == "cpe:/o:hp:integrated_lights-out_3_firmware" ) {
  if( version_is_less( version:version, test_version:"1.88" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.88" );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else if( cpe == "cpe:/o:hp:integrated_lights-out_4_firmware" ) {
  if( version_is_less( version:version, test_version:"2.44" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"2.44" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

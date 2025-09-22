# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103783");
  script_cve_id("CVE-2012-3271");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2023-07-27T05:05:08+0000");
  script_name("HP Integrated Lights-Out (iLO) Unspecified Information Disclosure Vulnerability");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-10 18:14:19 +0200 (Tue, 10 Sep 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("ilo_detect.nasl");
  script_mandatory_keys("hp/ilo/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56597");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to gain access to sensitive
  information that may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"insight", value:"Allows remote attackers to obtain sensitive information via unknown vectors.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"HP Integrated Lights-Out (iLO) is prone to an unspecified information
  disclosure vulnerability.");

  script_tag(name:"affected", value:"Integrated Lights-Out 3 (aka iLO3) with firmware before 1.50 and
  Integrated Lights-Out 4 (aka iLO4) with firmware before 1.13.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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
  if( version_is_less( version:version, test_version:"1.50" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.50" );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else if( cpe == "cpe:/o:hp:integrated_lights-out_4_firmware" ) {
  if( version_is_less( version:version, test_version:"1.13" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.13" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

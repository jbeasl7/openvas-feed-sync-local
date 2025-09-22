# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103859");
  script_cve_id("CVE-2013-4842", "CVE-2013-4843");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_name("HP Integrated Lights-Out (iLO) Multiple Vulnerabilities");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-18 11:18:02 +0100 (Wed, 18 Dec 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("ilo_detect.nasl");
  script_mandatory_keys("hp/ilo/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63691");

  script_tag(name:"impact", value:"An attacker may leverage this issue to obtain sensitive information that may
  aid in further attacks or to execute arbitrary HTML and script code in an unsuspecting user's browser in the
  context of the affected site. This may allow the attacker to steal cookie-based authentication credentials and
  launch other attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"HP Integrated Lights-Out is prone to a Cross Site Scripting and an
  Information Disclosure Vulnerability.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"HP Integrated Lights-Out (iLO) is prone to multiple vulnerabilities.");

  script_tag(name:"affected", value:"Versions prior to HP Integrated Lights-Out 4 1.32 and HP Integrated
  Lights-Out 3 1.65 are vulnerable.");

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
  if( version_is_less( version:version, test_version:"1.65" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.65" );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else if( cpe == "cpe:/o:hp:integrated_lights-out_4_firmware" ) {
  if( version_is_less( version:version, test_version:"1.32" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.32" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

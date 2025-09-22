# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903044");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-10-25 16:57:46 +0530 (Thu, 25 Oct 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2012-3155");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish / Java System Application Server CORBA ORB Subcomponent DoS Vulnerability (Oct 2012)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_eclipse_glassfish_http_detect.nasl", "secpod_sun_java_app_serv_detect.nasl");
  script_mandatory_keys("glassfish_or_sun_java_appserver/installed");

  script_tag(name:"summary", value:"Oracle GlassFish / Java System Application Server is prone to a
  denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused due to an unspecified error within the CORBA
  ORB subcomponent, which allows remote users to cause a denial of service condition.");

  script_tag(name:"impact", value:"Successful exploitation could allow malicious attackers to cause
  a denial of service.");

  script_tag(name:"affected", value:"Oracle GlassFish version 2.1.1, 3.0.1 and 3.1.2 and Oracle
  Java System Application Server version 8.1 and 8.2.");

  script_tag(name:"solution", value:"Apply the security updates.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51017/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56073");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:oracle:glassfish_server", "cpe:/a:sun:java_system_application_server" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! infos = get_app_version_and_location( cpe:cpe, port:port, exit_no_version:TRUE ) )
  exit(0);

vers = infos["version"];
path = infos["location"];

if( cpe == "cpe:/a:oracle:glassfish_server" ) {
  if( version_is_equal( version:vers, test_version:"3.0.1" ) ||
      version_is_equal( version:vers, test_version:"3.1.2" ) ||
      version_is_equal( version:vers, test_version:"2.1.1" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
} else if( cpe == "cpe:/a:sun:java_system_application_server" ) {

  vers = ereg_replace( pattern:"_", replace:".", string:vers );
  if( version_is_equal( version:vers, test_version:"8.1" ) ||
      version_is_equal( version:vers, test_version:"8.2" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

exit( 0 );

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sun:java_system_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801147");
  script_version("2023-09-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-09-15 05:06:15 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2009-11-12 15:21:24 +0100 (Thu, 12 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Sun Java System Web Server < 7.0 Update 7 Buffer Overflow Vulnerability");
  script_cve_id("CVE-2009-3878");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_sun_one_java_sys_web_serv_ssh_login_detect.nasl", "gb_sun_oracle_web_server_http_detect.nasl");
  script_mandatory_keys("sun/java_system_web_server/detected");

  script_xref(name:"URL", value:"http://intevydis.com/vd-list.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36813");
  script_xref(name:"URL", value:"http://www.intevydis.com/blog/?p=79");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37115");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3024");

  script_tag(name:"summary", value:"Sun Java Web Server is prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to execute arbitrary
  code in the context of an affected system.");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 6 and prior.");

  script_tag(name:"insight", value:"An unspecified error that can be exploited to cause a buffer
  overflow.");

  script_tag(name:"solution", value:"Update to version 7.0 update 7 or later.");

  # nb: The Remote-VT is only reporting the major version like 7.0.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port:port, cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"7.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0.7", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

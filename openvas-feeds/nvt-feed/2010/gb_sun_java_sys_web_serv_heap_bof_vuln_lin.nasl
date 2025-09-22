# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sun:java_system_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800160");
  script_version("2023-09-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-09-15 05:06:15 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0387");
  script_name("Sun Java System Web Server < 7.0 Update 8 Multiple Heap-based Buffer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_sun_one_java_sys_web_serv_ssh_login_detect.nasl", "gb_sun_oracle_web_server_http_detect.nasl");
  script_mandatory_keys("sun/java_system_web_server/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55792");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37896");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023488.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-digest.html");

  script_tag(name:"summary", value:"Sun Java Web Server is prone to multiple heap-based buffer
  overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in webservd and admin server that can be
  exploited to overflow a buffer and execute arbitrary code on the system or cause the server to
  crash via a long string in an 'Authorization: Digest' HTTP header.");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to cause the
  application to crash or execute arbitrary code on the system by sending an overly long request in
  an 'Authorization: Digest' header.");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 7 and prior.");

  script_tag(name:"solution", value:"Update to version 7.0 update 8 or later.");

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

if( version_is_less_equal( version:vers, test_version:"7.0.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0.8", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

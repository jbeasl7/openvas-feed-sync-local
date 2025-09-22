# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sun:java_system_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800156");
  script_version("2023-09-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-09-15 05:06:15 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0272", "CVE-2010-0273", "CVE-2010-0360", "CVE-2010-0361",
                "CVE-2010-0388", "CVE-2010-0389");
  script_name("Sun Java System Web Server 7.0 Update 6 / 7.0 Update 7 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_sun_one_java_sys_web_serv_ssh_login_detect.nasl", "gb_sun_oracle_web_server_http_detect.nasl");
  script_mandatory_keys("sun/java_system_web_server/detected");

  script_xref(name:"URL", value:"http://intevydis.com/sjws_demo.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37910");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55812");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-admin.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-webdav.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-trace.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-webdav.html");

  script_tag(name:"summary", value:"Sun Java Web Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- An error exists in WebDAV implementation in webservd and can
  be exploited to cause a Stack-based buffer overflow via long URI in an HTTP OPTIONS request.

  - An unspecified error that can be exploited to cause a heap-based buffer overflow which allows
  remote attackers to discover process memory locations and execute arbitrary code by sending a
  process memory address via crafted data.

  - Format string vulnerability in the WebDAV implementation in webservd that can be exploited to
  cause a denial of service via format string specifiers in the encoding attribute of the XML
  declaration in a PROPFIND request.

  - An unspecified error in admin server that can be exploited to cause a denial of service via an
  HTTP request that lacks a method token.");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to discover process
  memory locations or execute arbitrary code in the context of an affected system or cause the
  application to crash via a long URI in an HTTP OPTIONS request.");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 6 and 7.0
  update 7.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  # nb: The Remote-VT is only reporting the major version like 7.0.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"WillNotFix");

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

if( version_is_equal( version:vers, test_version:"7.0.6" ) ||
    version_is_equal( version:vers, test_version:"7.0.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"WillNotFix", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

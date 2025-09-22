# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900499");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-1191");
  script_name("Apache HTTP Server 'mod_proxy_ajp' Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34663");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50059");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc/httpd/httpd/trunk/CHANGES?r1=766938&r2=767089");
  script_xref(name:"URL", value:"https://archive.apache.org/dist/httpd/patches/apply_to_2.2.11/PR46949.diff");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_22.html");

  script_tag(name:"insight", value:"This flaw is due to an error in 'mod_proxy_ajp' when
  handling improperly malformed POST requests.");

  script_tag(name:"solution", value:"Update to Apache HTTP version 2.2.12 or later.

  Workaround:

  Update mod_proxy_ajp.c through SVN Repository (Revision 767089), see the references
  for a patch file containing an update.");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to an information disclosure
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a
  special HTTP POST request and gain sensitive information about the web server.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.2.11 running mod_proxy_ajp.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_equal( version:vers, test_version:"2.2.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.12", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

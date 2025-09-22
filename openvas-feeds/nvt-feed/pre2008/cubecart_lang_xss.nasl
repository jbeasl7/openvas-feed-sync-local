# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17227");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2005-0442", "CVE-2005-0443");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CubeCart < 2.0.5 index.php language XSS Vulnerability");
  # nb: Seems ACT_MIXED_ATTACK had been used because either the XSS check below is not that reliable
  # or because of the mixed usage of version and active check.
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cubecart/installed");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210218045523/http://www.securityfocus.com/bid/12549");

  script_tag(name:"summary", value:"CubeCart is prone to cross-site scripting (XSS) and remote
  script injection vulnerabilities due to a lack of sanitization of user-supplied data.");

  script_tag(name:"vuldetect", value:"Depending on the 'safe_checks' setting of the scan
  configuration:

  - Setting 'yes': Checks if a vulnerable version is present on the target host

  - Setting 'no': Sends a crafted HTTP GET request and checks the response");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to
  execute malicious script code on a vulnerable server.");

  script_tag(name:"affected", value:"CubeCart versions prior to 2.0.5.");

  script_tag(name:"solution", value:"Update to version 2.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

dir = infos["location"];
rep_dir = dir;

if( ! safe_checks() ) {

  vtstrings = get_vt_strings();

  if( dir == "/" )
    dir = "";

  url = string( dir, "/upload/index.php?&language=<script>", vtstrings["lowercase"], "-xss-test</script>" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 200" && egrep( pattern:"<script>" + vtstrings["lowercase"] + "-xss-test</script>", string:res ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( ! version = infos["version"] )
  exit( 0 );

if( version_is_less_equal( version:version, test_version:"2.0.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.0.5", install_url:rep_dir );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2001 HD Moore & Drew Hintz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10831");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2001-1204");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Total PC Solutions PHP Rocket Add-in for FrontPage File Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 HD Moore & Drew Hintz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210129080536/http://www.securityfocus.com/bid/3751");

  script_tag(name:"summary", value:"There is a vulnerability in the Total PC Solutions PHP Rocket
  Add-in for FrontPage that allows a remote attacker to view the contents of any arbitrary file to
  which the web user has access.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"This vulnerability exists because the PHP Rocket Add-in does not
  filter out ../ and is therefore susceptible to this directory traversal attack.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

files = traversal_files();

foreach check( make_list( "/phprocketaddin/", "/index.php" ) ) {

  res = http_get_cache( item:check, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  foreach file( keys( files ) ) {

    url = check + "?page=" + crap( data:"../", length:3 * 15 ) + files[file];

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

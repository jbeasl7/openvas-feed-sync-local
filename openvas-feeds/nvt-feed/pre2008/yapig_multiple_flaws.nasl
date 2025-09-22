# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18523");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1881", "CVE-2005-1882", "CVE-2005-1883", "CVE-2005-1884", "CVE-2005-1885", "CVE-2005-1886");
  script_xref(name:"OSVDB", value:"17115");
  script_xref(name:"OSVDB", value:"17116");
  script_xref(name:"OSVDB", value:"17117");
  script_xref(name:"OSVDB", value:"17118");
  script_xref(name:"OSVDB", value:"17119");
  script_xref(name:"OSVDB", value:"17120");
  script_xref(name:"OSVDB", value:"17121");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("YaPiG Multiple Flaws");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to YaPiG 0.95b or later.");

  script_tag(name:"summary", value:"The remote web server contains a PHP application that is affected by
multiple flaws.

Description :

The remote host is running YaPiG, a web-based image gallery written in
PHP.

The installed version of YaPiG is vulnerable to multiple flaws:

  - Remote and local file inclusion.

  - Cross-site scripting and HTML injection flaws through 'view.php'.

  - Directory traversal flaw through 'upload.php'.");
  script_xref(name:"URL", value:"http://secwatch.org/advisories/secwatch/20050530_yapig.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13871");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13874");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13875");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13876");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13877");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/yapig", "/gallery", "/photos", "/photo", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) continue;

  #Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
  if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9]($|[^0-9])|9([0-4][a-z]|5a))", string:res)) {
    security_message( port:port );
    exit(0);
  }
}

exit( 99 );

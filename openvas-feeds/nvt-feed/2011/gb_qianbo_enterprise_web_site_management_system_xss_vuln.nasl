# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801925");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Qianbo Enterprise Web Site Management System Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100425/qianbo-xss.txt");
  script_xref(name:"URL", value:"http://www.rxtx.nl/qianbo-enterprise-web-site-management-system-cross-site-scripting-2/");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could result in a compromise of the
  application, theft of cookie-based authentication credentials.");

  script_tag(name:"affected", value:"Qianbo Enterprise Web Site Management System.");

  script_tag(name:"insight", value:"The flaw is due to failure in the 'en/Search.Asp?' script to
  properly sanitize user-supplied input in 'Range=Product&Keyword' variable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Qianbo Enterprise Web Site Management System is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port)) exit(0);

foreach dir( make_list_unique( "/qianbo", "/enqianbo", "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir,"/en/index.asp"), port:port);
  if('QianboEmail' >< res && 'QianboSubscribe' >< res)
  {
    url = string(dir, '/en/Search.Asp?Range=Product&Keyword=<script>alert("XSS-TEST")</script>');
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && '><script>alert("XSS-TEST")</script>' >< res) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

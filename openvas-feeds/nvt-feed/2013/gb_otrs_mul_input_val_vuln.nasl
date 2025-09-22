# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803935");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-09-25 15:32:50 +0530 (Wed, 25 Sep 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2005-3893", "CVE-2005-3894", "CVE-2005-3895");

  script_name("OTRS 1.x <= 1.3.2, 2.x <= 2.0.3 Multiple Input Validation Vulnerabilities");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS)) is prone to multiple input
  validation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to login with provided credentials, sends a crafted HTTP
  GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2005-3893: Multiple SQL injection vulnerabilities

  - CVE-2005-3894: Multiple XSS vulnerabilities

  - CVE-2005-3895: OTRS, when AttachmentDownloadType is set to inline, renders text/html e-mail
  attachments as HTML in the browser when the queue moderator attempts to download the attachment,
  which allows remote attackers to execute arbitrary web script or HTML");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the
  victim's cookie-based authentication credentials or execute arbitrary SQL commands and bypass
  authentication.");

  script_tag(name:"affected", value:"OTRS version 1.x through 1.3.2 and 2.x through 2.0.3.");

  script_tag(name:"solution", value:"Update to version 1.3.3, 2.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/17685");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15537");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/34164");
  script_xref(name:"URL", value:"http://www.otrs.com/en/open-source/community-news/security-advisories/security-advisory-2005-01/");
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

function get_otrs_login_cookie(location, otrsport, otrshost) {
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

if(cookie) {
  url = loca + '/index.pl?QueueID="><script>alert(document.cookie)</script>"';
  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, " \r\n",
               "Connection: keep-alive\r\n",
               "Cookie: Session=", cookie, "\r\n\r\n");
  res = http_send_recv(port:port, data:req);

  if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) &&
     "<script>alert(document.cookie)</script>" >< res && "Logout" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);

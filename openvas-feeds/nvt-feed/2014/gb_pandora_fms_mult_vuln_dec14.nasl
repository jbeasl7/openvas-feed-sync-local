# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:artica:pandora_fms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805204");
  script_version("2025-08-12T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-12 05:40:06 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-12-04 12:25:10 +0530 (Thu, 04 Dec 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-125115");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pandora FMS < 5.1 SP1 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pandora_fms_http_detect.nasl");
  script_mandatory_keys("pandora_fms/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Pandora FMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The application installs with default user credentials.

  - CVE-2014-125115: An input passed to index.php script via the 'user' parameter is not properly
  sanitized before returning to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain privileged
  access, inject or manipulate SQL queries in the backend database allowing for the manipulation or
  disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Pandora FMS version 5.0 SP2 and prior.");

  script_tag(name:"solution", value:"Update to version 5.1 SP1 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35380");
  script_xref(name:"URL", value:"https://web.archive.org/web/20140304121149/http://blog.pandorafms.org/?p=2041");
  script_xref(name:"URL", value:"https://web.archive.org/web/20140331231237/http://pandorafms.com/downloads/whats_new_5-SP3.pdf");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

url = dir + "/mobile/index.php";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

input = eregmatch(pattern: "input([0-9a-z]+).*id", string: res);
if (isnull(input[1]))
  exit(0);

postData = string("action=login&user=%27SQL-Injection-Test&password=test&input", input[1], "=Login");

headers = make_array("Content-Type", "application/x-www-form-urlencoded");

req = http_post_put_req(port: port, url: url, data: postData, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (res && res =~ ">SQL error<.*SQL-Injection-Test" && ">Pandora FMS mobile<" >< res) {
  report = 'The response indicates a successful SQL injection.\n\nResponse:\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

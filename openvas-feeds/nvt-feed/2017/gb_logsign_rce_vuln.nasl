# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:logsign:logsign";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106651");
  script_version("2024-08-23T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2017-03-14 12:58:36 +0700 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Logsign RCE Vulnerability (Mar 2017) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_logsign_http_detect.nasl");
  script_mandatory_keys("logsign/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Logsign is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Logsign has a publicly accessible endpoint. That endpoint takes
  a user input and then use it during operating system command execution without proper
  validation.");

  script_tag(name:"solution", value:"Logsign provides a patch to solve this vulnerability.");

  script_xref(name:"URL", value:"https://pentest.blog/unexpected-journey-3-visiting-another-siem-and-uncovering-pre-auth-privileged-remote-code-execution/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/api/log_browser/validate";

rand = rand_str(length: 15, charset: "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz");

data = '{"file":"'+ rand + '.raw"}';

headers = make_array("Content-Type", "application/json");

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if ('{"message": "success", "success": true}' >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

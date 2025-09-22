# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147825");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2022-03-22 03:18:32 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-29 14:49:00 +0000 (Tue, 29 Mar 2022)");

  script_cve_id("CVE-2022-26148");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Grafana Information Disclosure Vulnerability (Feb 2022) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/http/detected");
  script_require_ports("Services/www", 3000);

  script_tag(name:"summary", value:"Grafana is prone to an information disclosure vulnerability
  when integrated with Zabbix.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"The Zabbix password can be found in the api_jsonrpc.php HTML
  source code. When the user logs in and allows the user to register, one can right click to view
  the source code and use Ctrl-F to search for password in api_jsonrpc.php to discover the Zabbix
  account password and URL address.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://2k8.org/post-319.html");

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

url = dir + "/";

pattern = '"password":"[^"]+"';
if (res = http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE,
                          icase: FALSE, extra_check: '"name":"Zabbix"')) {
  report = http_report_vuln_url(port: port, url: url);
  pwd = eregmatch(string: res, pattern: pattern, icase: FALSE);
  if (pwd)
    report += '\nExtracted Password: ' + pwd[0];
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

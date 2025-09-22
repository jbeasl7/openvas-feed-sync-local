# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:greenbone:greenbone_security_assistant";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108664");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-10-10 06:28:14 +0000 (Thu, 10 Oct 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-25 01:14:00 +0000 (Fri, 25 Jun 2021)");

  script_cve_id("CVE-2018-25016");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Greenbone Security Assistant (GSA) < 7.0.3 Host Header Injection Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_greenbone_gsa_http_detect.nasl", "gb_greenbone_os_consolidation.nasl", "smtp_settings.nasl"); # nb: The setting for get_3rdparty_domain() is currently located in this VT.
  script_mandatory_keys("greenbone/gsa/pre80/http/detected");
  script_exclude_keys("greenbone/gos/detected");

  script_tag(name:"summary", value:"Greenbone Security Assistant (GSA) is prone to an HTTP host
  header injection vulnerability.");

  script_tag(name:"impact", value:"An attacker can potentially use this vulnerability in a phishing
  attack.");

  script_tag(name:"affected", value:"Greenbone Security Assistant (GSA) before version 7.0.3.");

  script_tag(name:"solution", value:"Update to version 7.0.3 or later.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_xref(name:"URL", value:"https://github.com/greenbone/gsa/pull/318");
  script_xref(name:"URL", value:"https://github.com/greenbone/gsa/releases/tag/v7.0.3");

  exit(0);
}

if (get_kb_item("greenbone/gos/detected")) # Covered by 2019/greenbone/gb_gos_host_header_vuln_active.nasl
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("smtp_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

domain = get_3rdparty_domain();
replace = "Host: " + domain;
url = dir + "/";

req = http_get(port: port, item: url);
req = ereg_replace(string: req, pattern: '(Host: [^\r\n]+)', replace: replace);
res = http_keepalive_send_recv(port: port, data: req);
if (!res || res !~ "^HTTP/1\.[01] 303")
  exit(0);

if (found = egrep(string: res, pattern: '<html><body>Code 303 - Redirecting to .+' + domain + '.+<a/></body></html>', icase: TRUE)) {

  info['HTTP Method'] = "GET";
  info['URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  info['"Host" header'] = replace;

  report  = 'By doing the following request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'it was possible to redirect to an external ';
  report += 'domain via an HTTP Host header injection attack.';
  report += '\n\nResult:\n\n' + chomp(found);

  expert_info = 'Request:\n'+ req + 'Response:\n' + res + '\n';
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(99);

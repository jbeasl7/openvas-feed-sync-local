# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:zyxel:nas";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155118");
  script_version("2025-08-11T05:44:29+0000");
  script_tag(name:"last_modification", value:"2025-08-11 05:44:29 +0000 (Mon, 11 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-07 07:07:26 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 02:15:43 +0000 (Thu, 30 Nov 2023)");

  script_cve_id("CVE-2023-27992", "CVE-2023-35137", "CVE-2023-35138", "CVE-2023-37927",
                "CVE-2023-37928", "CVE-2023-4473", "CVE-2023-4474");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zyxel NAS Multiple Vulnerabilities (Jun/Nov 2023) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zyxel_nas_http_detect.nasl");
  script_mandatory_keys("zyxel/nas/http/detected");
  script_require_ports("Services/www", 5000);

  script_tag(name:"summary", value:"Multiple Zyxel NAS devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-27992: Pre-authentication command injection

  - CVE-2023-35137: Improper authentication in the authentication module

  - CVE-2023-35138: Command injection in the 'show_zysync_server_contents' function

  - CVE-2023-37927: Improper neutralization of special elements in the CGI program

  - CVE-2023-37928: Post-authentication command injection in the WSGI server

  - CVE-2023-4473: Command injection in the web server

  - CVE-2023-4474: Improper neutralization of special elements in the WSGI server");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-pre-authentication-command-injection-vulnerability-in-nas-products");
  script_xref(name:"URL", value:"https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-authentication-bypass-and-command-injection-vulnerabilities-in-nas-products");
  script_xref(name:"URL", value:"https://www.ibm.com/think/x-force/ibm-identifies-zero-day-vulnerability-zyxel-nas-devices");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url = "/cmd,/ck6fup6/zylog_main/configure_mail_syslog";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^HTTP/1\.[01] 302")
  exit(0);

url = "/cmd,/ck6fup6/zylog_main/configure_mail_syslog/favicon.ico";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && res =~ '\\{"errorMsg"\\s*:\\s*"OK"\\}') {
  report = "The response from a GET request to " + http_report_vuln_url(port: port, url: url, url_only: TRUE) +
           " indicates that authentication bypass is possible which could be used in conjunction with" +
           ' additional vulnerabilities.\n\nResponse:\n\n' + chomp(res);
  security_message(port: port, data: report);
  exit(0);
}

exit(0); # nb: Check not fully reliable so we don't mark it as not affected

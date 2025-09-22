# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ruckuswireless:unleashed_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143324");
  script_version("2025-07-24T05:43:49+0000");
  script_tag(name:"last_modification", value:"2025-07-24 05:43:49 +0000 (Thu, 24 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-01-08 08:39:38 +0000 (Wed, 08 Jan 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-23 21:55:00 +0000 (Thu, 23 Jan 2020)");

  script_cve_id("CVE-2019-19834", "CVE-2019-19835", "CVE-2019-19836", "CVE-2019-19837",
                "CVE-2019-19838", "CVE-2019-19839", "CVE-2019-19840", "CVE-2019-19841",
                "CVE-2019-19842", "CVE-2019-19843");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ruckus Unleashed Multiple Vulnerabilities (Jan 2020) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ruckus_unleashed_http_detect.nasl");
  script_mandatory_keys("ruckus/unleashed/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Ruckus Unleashed is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP GET requests and checks the responses.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-19834: Command injection vulnerability via a crafted CLI command with admin privilege

  - CVE-2019-19835: SSRF vulnerability in zap, caused by insufficient input validation

  - CVE-2019-19836: Remote code execution vulnerability in zap caused by insufficient input
  validation

  - CVE-2019-19837: Information disclosure vulnerability

  - CVE-2019-19838, CVE-2019-19839, CVE-2019-19841, CVE-2019-19842: Remote command injection via a
  crafted HTTP request, caused by insufficient input validation

  - CVE-2019-19840: Stack buffer overflow/remote code execution vulnerability via acrafted
  unauthenticated HTTP request

  - CVE-2019-19843: Access control vulnerability resulting in sensitive information disclosure");

  script_tag(name:"affected", value:"Ruckus Unleashed through version 200.6 and version 200.7.");

  script_tag(name:"solution", value:"Update to firmware version 200.7.10.202.94 or later.");

  script_xref(name:"URL", value:"https://support.ruckuswireless.com/security_bulletins/299");
  script_xref(name:"URL", value:"https://alephsecurity.com/2020/01/14/ruckus-wireless/");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/user/wps_tool_cache/var/run/rpmkey.rev";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

revnum = eregmatch(pattern: "([0-9]+)", string: res);
if (isnull(revnum[1]))
  exit(0);

url = "/user/wps_tool_cache/var/run/rpmkey" + revnum[1];

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

res = bin2string(ddata: res, noprint_replacement: "");

if (res =~ "^HTTP/1\.[01] 200" && "all_powerful_login_password" >< res) {
  report = "It was possible to obtain sensitive information (e.g. admin credentials) at " +
           http_report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

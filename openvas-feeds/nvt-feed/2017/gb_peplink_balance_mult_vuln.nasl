# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:peplink:balance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106848");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-06-06 10:51:07 +0700 (Tue, 06 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-8835", "CVE-2017-8836", "CVE-2017-8837", "CVE-2017-8838", "CVE-2017-8839",
                "CVE-2017-8840", "CVE-2017-8841");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Peplink Balance Routers Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_peplink_balance_webadmin_detect.nasl");
  script_mandatory_keys("peplink_balance/detected");

  script_tag(name:"summary", value:"Peplink Balance routers are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Peplink Balance routers are prone to multiple vulnerabilities:

  - SQL injection attack via the 'bauth' cookie parameter (CVE-2017-8835)

  - No CSRF Protection (CVE-2017-8836)

  - Passwords stored in Cleartext (CVE-2017-8837)

  - XSS via syncid Parameter (CVE-2017-8838)

  - XSS via preview.cgi (CVE-2017-8839)

  - File Deletion (CVE-2017-8841)

  - Information Disclosure (CVE-2017-8840)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"affected", value:"Peplink Balance Router firmware 7.0.0-build1904 and possible prior.");

  script_tag(name:"solution", value:"Update to firmware version 7.0.1-build2093 or later.");

  script_xref(name:"URL", value:"https://www.x41-dsec.de/lab/advisories/x41-2017-005-peplink/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/cgi-bin/HASync/hasync.cgi?debug=1";

if (http_vuln_check(port: port, url: url, pattern: "Master LAN Address", check_header: TRUE,
                    extra_check: "HA Group ID")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

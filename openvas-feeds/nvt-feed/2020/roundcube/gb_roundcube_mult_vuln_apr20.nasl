# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:roundcube:webmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143823");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-05-06 03:39:03 +0000 (Wed, 06 May 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-24 18:15:00 +0000 (Thu, 24 Sep 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-12625", "CVE-2020-12626", "CVE-2020-12640", "CVE-2020-12641");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.2.10, 1.3.x < 1.3.11, 1.4.x < 1.4.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-12625: Cross-site scripting (XSS) via malicious HTML content

  - CVE-2020-12626: Cross-site request forgery (CSRF) attack can cause an authenticated user to be
  logged out

  - CVE-2020-12640: Path traversal vulnerability allowing local file inclusion via crafted 'plugins'
  option

  - CVE-2020-12641: Remote code execution (RCE) via crafted config options");

  script_tag(name:"affected", value:"Roundcube Webmail versions before 1.2.10, 1.3.11 and 1.4.4.");

  script_tag(name:"solution", value:"Update to version 1.2.10, 1.3.11, 1.4.4 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2020/04/29/security-updates-1.4.4-1.3.11-and-1.2.10");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.3", test_version2: "1.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.4", test_version2: "1.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

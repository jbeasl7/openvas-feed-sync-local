# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:roundcube:webmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145132");
  script_version("2025-05-16T05:40:21+0000");
  script_tag(name:"last_modification", value:"2025-05-16 05:40:21 +0000 (Fri, 16 May 2025)");
  script_tag(name:"creation_date", value:"2021-01-13 09:08:57 +0000 (Wed, 13 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-13 04:15:00 +0000 (Wed, 13 Jan 2021)");

  script_cve_id("CVE-2020-35730");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.2.13, 1.3.x < 1.3.16, 1.4.x < 1.4.10 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can send a plain text e-mail message, with
  JavaScript in a link reference element that is mishandled by linkref_addindex in
  rcube_string_replacer.php.");

  script_tag(name:"affected", value:"Roundcube Webmail versions before 1.2.13, 1.3.16 and 1.4.10.");

  script_tag(name:"solution", value:"Update to version 1.2.13, 1.3.16, 1.4.10 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2020/12/27/security-updates-1.4.10-1.3.16-and-1.2.13");
  script_xref(name:"URL", value:"https://www.alexbirnberg.com/roundcube-xss.html");
  script_xref(name:"URL", value:"https://www.welivesecurity.com/en/eset-research/operation-roundpress/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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

if (version_is_less(version: version, test_version: "1.2.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.3", test_version2: "1.3.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.4", test_version2: "1.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

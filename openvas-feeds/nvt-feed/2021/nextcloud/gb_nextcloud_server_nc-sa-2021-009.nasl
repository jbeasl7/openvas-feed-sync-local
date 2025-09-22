# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146119");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2021-06-15 01:54:29 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-09 09:15:00 +0000 (Fri, 09 Jul 2021)");

  script_cve_id("CVE-2021-22915");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Brute-Force Protection Vulnerability (NC-SA-2021-009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a vulnerability in the brute-force
  protection.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nextcloud server is vulnerable to brute force attacks due to
  lack of inclusion of IPv6 subnets in rate-limiting considerations. This could potentially result
  in an attacker bypassing rate-limit controls such as the Nextcloud brute-force protection.");

  script_tag(name:"affected", value:"Nextcloud server prior to versions 19.0.11, 20.x through
  20.0.9 and 21.x through 21.0.1.");

  script_tag(name:"solution", value:"Update to version 19.0.11, 20.0.10, 21.0.2 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2021-009");

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

if (version_is_less(version: version, test_version: "19.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "20.0.0", test_version2: "20.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "21.0.0", test_version2: "21.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126104");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2022-08-08 13:04:16 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-10 15:31:00 +0000 (Wed, 10 Aug 2022)");

  script_cve_id("CVE-2022-31118");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 22.2.9, 23.x < 23.0.6, 24.x < 24.0.2 Improper Initialization (GHSA-2vwh-5v93-3vcq)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an insufficient logging
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker could brute force to find if federated sharing is
  being used and potentially try to brute force access tokens for federated shares a-zA-Z0-9^15.");

  script_tag(name:"affected", value:"Nextcloud Server prior to version 22.2.9, 23.x through 23.0.5
  and 24.x through 24.0.1.");

  script_tag(name:"solution", value:"Update to version 22.2.9, 23.0.6, 24.0.2 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-2vwh-5v93-3vcq");

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

if (version_is_less(version: version, test_version: "22.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.2.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "23.0", test_version_up: "23.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "24.0", test_version_up: "24.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

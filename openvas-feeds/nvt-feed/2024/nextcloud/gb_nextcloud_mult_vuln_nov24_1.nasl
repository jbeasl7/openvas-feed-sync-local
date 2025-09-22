# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153497");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-21 14:53:17 +0000 (Thu, 21 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-23 14:33:48 +0000 (Thu, 23 Jan 2025)");

  script_cve_id("CVE-2024-52518", "CVE-2024-52523", "CVE-2024-52525");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 28.x < 28.0.12, 29.x < 29.0.9, 30.x < 30.0.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-52518: Missing password confirmation when changing external storage options

  - CVE-2024-52523: Custom defined credentials of external storages are sent back to the frontend

  - CVE-2024-52525: User password is available in memory of the PHP process");

  script_tag(name:"affected", value:"Nextcloud Server version 28.x prior to 28.0.12, 29.x prior to
  29.0.9 and 30.x prior to 30.0.2.");

  script_tag(name:"solution", value:"Update to version 28.0.12, 29.0.9, 30.0.2 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-vrhf-532w-99rg");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-42w6-r45m-9w9j");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-w7v5-mgxm-v6gm");

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

if (version_in_range_exclusive(version: version, test_version_lo: "28.0.0", test_version_up: "28.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "28.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "29.0.0", test_version_up: "29.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "29.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "30.0.0", test_version_up: "30.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "30.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

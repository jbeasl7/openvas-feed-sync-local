# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146691");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2021-09-09 13:35:29 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-14 16:54:00 +0000 (Tue, 14 Sep 2021)");

  script_cve_id("CVE-2021-32766", "CVE-2021-32800", "CVE-2021-32801", "CVE-2021-32802");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Multiple Vulnerabilities (Sep 2021)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-32766: Nextcloud Text app can disclose existence of folders in 'File Drop' link share

  - CVE-2021-32800: Bypass of Two Factor Authentication

  - CVE-2021-32801: Exceptions may have logged Encryption-at-Rest key content

  - CVE-2021-32802: Preview generation used third-party library not suited for user-generated content");

  script_tag(name:"affected", value:"Nextcloud server 20.0.11 and prior, 21.0.x through 21.0.3 and
  22.x prior to 22.1.0.");

  script_tag(name:"solution", value:"Update to version 20.0.12, 21.0.4, 22.1.0 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-gv5w-8q25-785v");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-mcpf-v65v-359h");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-m682-v4g9-wrq7");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-gcf3-3wmc-88jr");

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

if (version_is_less(version: version, test_version: "20.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "21.0.0", test_version2: "21.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^22\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

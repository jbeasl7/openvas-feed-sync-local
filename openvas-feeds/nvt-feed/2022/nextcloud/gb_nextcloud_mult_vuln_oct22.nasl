# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127235");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2022-10-31 09:11:11 +0000 (Mon, 31 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-31 14:26:00 +0000 (Mon, 31 Oct 2022)");

  script_cve_id("CVE-2022-39329", "CVE-2022-39364");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 23.0.9, < 24.0.5 Multiple Information Disclosure Vulnerabilities (GHSA-8f3p-rcm5-mrg3, GHSA-qpf5-jj85-36h5)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple information disclosure
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-39329: Exposure of information that can not be controlled by administrators without
  direct database access.

  - CVE-2022-39364: When an attacker gets hold of the nextcloud.log, they may gain knowledge of
  credentials to connect to a SharePoint service.");

  script_tag(name:"affected", value:"Nextcloud Server prior to version 23.0.9 and 24.0.5.");

  script_tag(name:"solution", value:"Update to version 23.0.9, 24.0.5 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-8f3p-rcm5-mrg3");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-qpf5-jj85-36h5");

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

if (version_is_less(version: version, test_version: "23.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "24.0", test_version_up: "24.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

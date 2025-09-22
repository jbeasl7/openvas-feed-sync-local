# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153498");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-21 15:03:25 +0000 (Thu, 21 Nov 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-23 15:05:17 +0000 (Thu, 23 Jan 2025)");

  script_cve_id("CVE-2024-52519", "CVE-2024-52520", "CVE-2024-52521");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 28.x < 28.0.10, 29.x < 29.0.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-52519: OAuth2 client secrets were stored in a recoverable way

  - CVE-2024-52520: Link reference provider can be tricked into downloading bigger files than
  intended

  - CVE-2024-52521: Potential hash collision for background jobs could skip queuing them");

  script_tag(name:"affected", value:"Nextcloud Server version 28.x prior to 28.0.10 and 29.x prior
  to 29.0.7.");

  script_tag(name:"solution", value:"Update to version 28.0.10, 29.0.7 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-fvpc-8hq6-jgq2");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-pxqf-cfxw-mqmj");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-2q6f-gjgj-7hp4");

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

if (version_in_range_exclusive(version: version, test_version_lo: "28.0.0", test_version_up: "28.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "28.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "29.0.0", test_version_up: "29.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "29.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

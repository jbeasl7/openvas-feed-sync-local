# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencast:opencast";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133061");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-02 06:43:25 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-55202");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Opencast < 17.7, 18.0 Path Traversal Vulnerability (GHSA-hq8m-v68g-8cf8)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"Opencast is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The protections against path traversal attacks in the UI
  config module are insufficient, still partially allowing for attacks in very specific cases. The
  path is checked without checking for the file separator. This could allow attackers access to
  files within another folder which starts with the same path.");

  script_tag(name:"affected", value:"Opencast prior to version 17.7 and 18.0 only.");

  script_tag(name:"solution", value:"Update to version 17.7, 18.1 or later.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-hq8m-v68g-8cf8");
  script_xref(name:"URL", value:"https://github.com/opencast/opencast/pull/6979");

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

if (version_is_less(version: version, test_version: "17.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "18.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

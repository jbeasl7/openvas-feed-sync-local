# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mantisbt:mantisbt";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143041");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-10-23 08:21:41 +0000 (Wed, 23 Oct 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 19:15:00 +0000 (Fri, 18 Sep 2020)");

  script_cve_id("CVE-2019-15715");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MantisBT < 1.3.20, 2.x < 2.22.1 RCE Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MantisBT is prone to an authenticated command injection
  vulnerability, leading to remote code execution (RCE).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MantisBT versions prior 1.3.20 and versions 2.x prior to 2.22.1.");

  script_tag(name:"solution", value:"Update to version 1.3.20, 2.22.1 or later.");

  script_xref(name:"URL", value:"https://mantisbt.org/bugs/changelog_page.php?project=mantisbt");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=26091");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=26162");

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

if (version_is_less(version: version, test_version: "1.3.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.0", test_version2: "2.22.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.22.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

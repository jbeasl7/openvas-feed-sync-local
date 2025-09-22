# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147919");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-04-05 03:07:38 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-11 19:44:00 +0000 (Mon, 11 Apr 2022)");

  script_cve_id("CVE-2022-1111");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 14.0.x < 14.7.7, 14.8.x < 14.8.5, 14.9.x < 14.9.2 Business Logic Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a business logic vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A business logic error in Project Import under certain
  conditions caused imported projects to show an incorrect user in the 'Access Granted' column in
  the project membership pages.");

  script_tag(name:"affected", value:"GitLab version 14.x prior to 14.7.7, 14.8.x prior to 14.8.5
  and 14.9.x prior to 14.9.2.");

  script_tag(name:"solution", value:"Update to version 14.7.7, 14.8.5, 14.9.2 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/03/31/critical-security-release-gitlab-14-9-2-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "14.0.0", test_version_up: "14.7.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.7.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.8.0", test_version_up: "14.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.8.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.9.0", test_version_up: "14.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.9.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170087");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-03-28 14:21:05 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-0882");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 8.7.x - 8.15.7, 8.16.x - 8.16.7, 8.17.x - 8.17.3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to an exposure of sensitive information to an
  unauthorized actor vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"JSON response in issue assignment leaks sensitive
  information.");

  script_tag(name:"affected", value:"GitLab version 8.7.x through 8.15.7, 8.16.x through 8.16.7
  and 8.17.x through 8.17.3.");

  script_tag(name:"solution", value:"Update to version 8.15.8, 8.16.8, 8.17.4 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2017/03/20/gitlab-8-dot-17-dot-4-security-release/");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/29661");

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

if (version_in_range(version: version, test_version: "8.7.0", test_version2: "8.15.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.15.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.16.0", test_version2: "8.16.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.16.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.17.0", test_version2: "8.17.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.17.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

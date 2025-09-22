# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148091");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-05-11 03:48:51 +0000 (Wed, 11 May 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-18 16:44:00 +0000 (Wed, 18 May 2022)");

  script_cve_id("CVE-2022-1417");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 8.12.x < 14.8.6, 14.9.x < 14.9.4, 14.10.x < 14.10.1 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper access control in GitLab CE/EE allows non-project
  members to access contents of Project Members-only Wikis via malicious CI jobs.");

  script_tag(name:"affected", value:"GitLab version 8.12.x prior to 14.8.6, 14.9.x prior to 14.9.4
  and 14.10.x prior to 14.10.1.");

  script_tag(name:"solution", value:"Update to version 14.8.6, 14.9.4, 14.10.1 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1417.json");
  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/05/02/security-release-gitlab-14-10-1-released/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.12.0", test_version_up: "14.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.8.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.9.0", test_version_up: "14.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.9.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.10.0", test_version_up: "14.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.10.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

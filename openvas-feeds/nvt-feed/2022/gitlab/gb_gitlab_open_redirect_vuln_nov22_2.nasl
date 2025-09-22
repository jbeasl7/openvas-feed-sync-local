# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170219");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-11-11 12:06:24 +0000 (Fri, 11 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-11 01:01:00 +0000 (Fri, 11 Nov 2022)");

  script_cve_id("CVE-2022-3280");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 10.1 < 15.3.5, 15.4 < 15.4.4, 15.5 < 15.5.2 Open Redirect Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An open redirect in GitLab CE/EE allows an attacker to trick
  users into visiting a trustworthy URL and being redirected to arbitrary content.");

  script_tag(name:"affected", value:"GitLab version 10.1.x and above prior to 15.3.5, 15.4.x prior
  to 15.4.4 and 15.5.x prior to 15.5.2.");

  script_tag(name:"solution", value:"Update to version 15.3.5, 15.4.4, 15.5.2 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-3280.json");

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

if (version_in_range_exclusive(version: version, test_version_lo: "10.1", test_version_up: "15.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.4", test_version_up: "15.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.5", test_version_up: "15.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

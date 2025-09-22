# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170086");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-03-28 14:21:05 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-15 18:19:00 +0000 (Mon, 15 May 2017)");

  script_cve_id("CVE-2017-8778");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab <= 8.14.8, 8.15.x - 8.15.5, 8.16.x - 8.16.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SVG files can contain Javascript in <script> tags. Browsers
  are smart enough to ignore scripts embedded in SVG files included via IMG tags. However, a direct
  request for a SVG file will result in the scripts being executed.");

  script_tag(name:"affected", value:"GitLab version 8.14.8 and prior, 8.15.x through 8.15.5 and
  8.16.x through 8.16.4.");

  script_tag(name:"solution", value:"Update to version 8.14.9, 8.15.6, 8.16.5 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2017/02/15/gitlab-8-dot-16-dot-5-security-release/");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/27471");

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

if (version_is_less(version: version, test_version: "8.14.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.14.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.15.0", test_version2: "8.15.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.15.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.16.0", test_version2: "8.16.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.16.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

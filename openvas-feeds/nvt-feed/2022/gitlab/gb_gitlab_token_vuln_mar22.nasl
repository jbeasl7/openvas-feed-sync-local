# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147910");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-04-05 02:29:34 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-11 19:42:00 +0000 (Mon, 11 Apr 2022)");

  script_cve_id("CVE-2022-1148");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 11.5.x < 14.7.7, 14.8.x < 14.8.5, 14.9.x < 14.9.2 Access Token Reuse Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to an access token reuse vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper authorization in GitLab Pages included with GitLab
  CE/EE allowed an attacker to steal a user's access token on an attacker-controlled private GitLab
  Pages website and reuse that token on the victim's other private websites.");

  script_tag(name:"affected", value:"GitLab version 11.5.x prior to 14.7.7, 14.8.x prior to 14.8.5
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

if (version_in_range_exclusive(version: version, test_version_lo: "11.5.0", test_version_up: "14.7.7")) {
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

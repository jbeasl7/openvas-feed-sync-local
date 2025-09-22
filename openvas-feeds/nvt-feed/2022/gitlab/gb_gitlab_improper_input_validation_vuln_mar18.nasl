# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170073");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-03-29 10:09:21 +0000 (Tue, 29 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 17:15:00 +0000 (Tue, 05 Mar 2019)");

  script_cve_id("CVE-2018-8971");

  script_tag(name:"qod_type", value:"executable_version_unreliable"); # nb: Backported on Debian, see https://www.debian.org/security/2018/dsa-4206

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab <= 10.3.7, 10.4.x - 10.4.4, 10.5.x - 10.5.4 Improper Input Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to an improper input validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Auth0 integration in GitLab has an incorrect
  omniauth-auth0 configuration, leading to signing in unintended users.");

  script_tag(name:"affected", value:"GitLab version 10.3.7 and prior, 10.4.x through 10.4.4 and
  10.5.x through 10.5.4.");

  script_tag(name:"solution", value:"Update to version 10.3.8, 10.4.5, 10.5.5 or later.");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4206");

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

if (version_is_less(version: version, test_version: "10.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.4.0", test_version2: "10.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

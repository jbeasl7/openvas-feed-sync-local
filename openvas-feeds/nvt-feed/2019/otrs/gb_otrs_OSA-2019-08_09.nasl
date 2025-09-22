# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108592");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2019-06-07 10:27:29 +0000 (Fri, 07 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-20 16:14:00 +0000 (Fri, 20 Jan 2023)");

  script_cve_id("CVE-2019-12248", "CVE-2019-12497");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 5.x < 5.0.36, 6.x < 6.0.19, 7.x < 7.0.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-12248: Loading external image resources

  - CVE-2019-12497: Information disclosure");

  script_tag(name:"affected", value:"OTRS versions 5.x prior to 5.0.26, 6.x prior to 6.0.19 and
  7.x prior to 7.0.8.");

  script_tag(name:"solution", value:"Update to version 5.0.36, 6.0.19, 7.0.8 or later.");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2019-08-security-update-for-otrs-framework/");
  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2019-09-security-update-for-otrs-framework/");

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

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

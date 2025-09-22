# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sensiolabs:symfony";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.153581");
  script_version("2024-12-06T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-12-06 05:05:38 +0000 (Fri, 06 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-05 08:45:09 +0000 (Thu, 05 Dec 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2024-50340");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symfony Environment Change Vulnerability (GHSA-x8vp-gf4q-mw5j)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to a vulnerability where it is possible to
  change the environment in a query.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When the register_argc_argv php directive is set to 'on' and
  users call any URL with a special crafted query string, they are able to change the environment
  or debug mode used by the kernel when handling the request.");

  script_tag(name:"affected", value:"Symfony prior to version 5.4.46, 6.x prior to 6.4.14 and 7.x
  prior to 7.1.7.");

  script_tag(name:"solution", value:"Update to version 5.4.46, 6.4.14, 7.1.7 or later.");

  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-x8vp-gf4q-mw5j");
  script_xref(name:"URL", value:"https://github.com/Nyamort/CVE-2024-50340");

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

if (version_is_less(version: version, test_version: "5.4.46")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.46", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.4.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

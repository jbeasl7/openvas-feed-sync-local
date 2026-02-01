# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133160");
  script_version("2026-01-13T05:47:36+0000");
  script_tag(name:"last_modification", value:"2026-01-13 05:47:36 +0000 (Tue, 13 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-07 10:10:41 +0000 (Wed, 07 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2025-69200");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ Improper Authorization Vulnerability (GHSA-9cg9-4h4f-j6fg)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to an improper authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unauthenticated remote attacker can trigger generation of a
  configuration backup ZIP via POST /api/setup/backup and then download the generated ZIP from a
  web-accessible location. The ZIP contains sensitive configuration files (e.g., database.php with
  database credentials).");

  script_tag(name:"impact", value:"Successful exploitation can lead to high-impact information
  disclosure and potential follow-on compromise.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 4.0.16 and 4.1.0-RC only.");

  script_tag(name:"solution", value:"Update to version 4.0.16, 4.1.0 final or later.");

  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-9cg9-4h4f-j6fg");

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

if (version_is_less(version: version, test_version: "4.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.16",
                            install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.1.0-rc")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.0 final",
                            install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

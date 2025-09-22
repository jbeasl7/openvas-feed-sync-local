# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126422");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2023-05-04 12:30:56 +0200 (Thu, 04 May 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-06 18:43:00 +0000 (Thu, 06 Jul 2023)");

  script_cve_id("CVE-2023-3469");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpmyFAQ < 3.2.0-beta.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A cross site scripting (XSS) has been identified when an
  administrator restores a backup from a file.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.2.0-beta.2.");

  script_tag(name:"solution", value:"Update to version 3.2.0-beta.2 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/3565cfc9-82c4-4db8-9b8f-494dd81b56ca/");

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

if (version_is_less(version: version, test_version: "3.2.0-beta.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.0-beta.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

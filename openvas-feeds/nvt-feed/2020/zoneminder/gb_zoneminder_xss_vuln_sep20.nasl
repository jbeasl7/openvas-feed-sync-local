# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoneminder:zoneminder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144593");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2020-09-18 03:08:24 +0000 (Fri, 18 Sep 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-24 14:42:00 +0000 (Thu, 24 Sep 2020)");

  script_cve_id("CVE-2020-25729", "CVE-2020-25730");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder < 1.34.21 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_http_detect.nasl");
  script_mandatory_keys("zoneminder/detected");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple cross-site scripting (XSS)
  vulnerabilities via the connkey parameter to download.php or export.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-25729: XSS via the connkey parameter to download.php or export.php.

  - CVE-2020-25730: ZoneMinder allows remote attackers execute arbitrary code, escalate privileges
  and obtain sensitive information via PHP_SELF component in classic/views/download.php.");

  script_tag(name:"affected", value:"ZoneMinder prior to version 1.34.21.");

  script_tag(name:"solution", value:"Update to version 1.34.21 or later.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/releases/tag/1.34.21");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/commit/9268db14a79c4ccd444c2bf8d24e62b13207b413");

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

if (version_is_less(version: version, test_version: "1.34.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.34.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112718");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-03-30 09:30:11 +0000 (Mon, 30 Mar 2020)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-23 15:15:00 +0000 (Wed, 23 Sep 2020)");

  script_cve_id("CVE-2020-1769", "CVE-2020-1770", "CVE-2020-1771", "CVE-2020-1772",
                "CVE-2020-1773");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 5.0.x < 5.0.42, 6.0.x < 6.0.27, 7.0.x < 7.0.16 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-1769: Autocomplete in the form login screens

  - CVE-2020-1770: Information disclosure in support bundle files

  - CVE-2020-1771: Possible XSS in Customer user address book

  - CVE-2020-1772: Information Disclosure

  - CVE-2020-1773: Session / Password / Password token leak");

  script_tag(name:"affected", value:"OTRS versions 5.0.x through 5.0.41, 6.0.x through 6.0.26 and
  7.0.x through 7.0.15.");

  script_tag(name:"solution", value:"Update to version 5.0.42, 6.0.27, 7.0.16 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2020-06/");
  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2020-07/");
  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2020-08/");
  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2020-09/");
  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2020-10/");

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

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.41")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.42", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

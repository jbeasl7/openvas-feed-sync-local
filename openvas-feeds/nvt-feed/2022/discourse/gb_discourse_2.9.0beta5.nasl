# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148230");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-06-08 03:55:05 +0000 (Wed, 08 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:20:00 +0000 (Mon, 27 Jun 2022)");

  script_cve_id("CVE-2021-41095", "CVE-2022-31025", "CVE-2022-31060");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 2.9.x < 2.9.0.beta5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-41095: XSS via blocked watched word in error message

  - CVE-2022-31025: User approval bypass

  - CVE-2022-31060: Banner topic data is exposed on login-required sites");

  script_tag(name:"affected", value:"Discourse version 2.9.x prior to 2.9.0.beta5.");

  script_tag(name:"solution", value:"Update to version 2.9.0.beta5 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-x7jh-mx5q-6f9q");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-5f4f-35fx-gqhq");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-qvqx-2h7w-m479");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/pull/14434");

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

if (version_in_range(version: version, test_version: "2.9.0.beta1", test_version2: "2.9.0.beta4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.0.beta5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

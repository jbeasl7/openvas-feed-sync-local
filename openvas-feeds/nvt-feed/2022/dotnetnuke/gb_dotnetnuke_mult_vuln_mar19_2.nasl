# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dnnsoftware:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126107");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2022-08-08 10:04:16 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 20:47:00 +0000 (Fri, 03 Mar 2023)");

  script_cve_id("CVE-2018-15811", "CVE-2018-15812");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DNN (DotNetNuke) 9.2.x < 9.2.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_consolidation.nasl");
  script_mandatory_keys("dotnetnuke/detected");

  script_tag(name:"summary", value:"DNN (formerly DotNetNuke) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-15811: Usage of a weak encryption algorithm to protect input parameters.

  - CVE-2018-15812: Incorrect conversion of encryption key source values, resulting in lower than
  expected entropy.");

  script_tag(name:"affected", value:"DNN versions 9.2.x prior to 9.2.2.");

  script_tag(name:"solution", value:"Update to version 9.2.2 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-h595-8pw6-5q6v");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-pf46-gqg9-j3v3");
  script_xref(name:"URL", value:"https://dnncommunity.org/security");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.2.0", test_version_up: "9.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

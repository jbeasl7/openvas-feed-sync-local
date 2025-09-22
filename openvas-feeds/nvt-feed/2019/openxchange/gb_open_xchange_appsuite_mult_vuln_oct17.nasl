# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142485");
  script_version("2024-02-21T05:06:27+0000");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-06-04 07:07:00 +0000 (Tue, 04 Jun 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-28 16:11:00 +0000 (Tue, 28 May 2019)");

  script_cve_id("CVE-2017-13667", "CVE-2017-13668", "CVE-2017-15029", "CVE-2017-15030");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Open-Xchange (OX) App Suite Multiple Vulnerabilities (Oct 2017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Open-Xchange (OX) App Suite is prone to multiple vulnerabilities:

  - SSRF (CVE-2017-13667, CVE-2017-15029)

  - Cross Site Scripting (CVE-2017-13668, CVE-2017-15030)");

  script_tag(name:"solution", value:"Update to version 7.8.3-rev32, 7.8.4-rev14 or later.");

  script_xref(name:"URL", value:"https://documentation.open-xchange.com/7.8.3/release-notes/release-notes.html");
  script_xref(name:"URL", value:"https://documentation.open-xchange.com/7.8.4/release-notes/release-notes.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!revision = get_kb_item("open-xchange/app_suite/" + port + "/revision"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
version += "." + revision;

if (version_is_less(version: version, test_version: "7.8.3.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.3.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.8.4", test_version2: "7.8.4.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

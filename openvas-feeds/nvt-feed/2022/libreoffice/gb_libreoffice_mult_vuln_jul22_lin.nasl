# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126085");
  script_version("2024-02-22T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-22 05:06:55 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-07-28 18:36:30 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-02 13:39:00 +0000 (Tue, 02 Aug 2022)");

  script_cve_id("CVE-2022-26306", "CVE-2022-26307");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Libre Office 7.2.x < 7.2.7, 7.3.x < 7.3.3 Multiple Vulnerabilities (Jul 2022) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_libre_office_detect_lin.nasl");
  script_mandatory_keys("LibreOffice/Linux/Ver");

  script_tag(name:"summary", value:"LibreOffice is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-26305: An attacker is allowed to create an arbitrary certificate,
  which may lead user to execute arbitrary code contained in improperly trusted macros.

  - CVE-2022-26306: Security weakness of the encryption allows attacker access,
  to the user's configuration data.");

  script_tag(name:"affected", value:"Libre Office 7.2.x through 7.2.7 and 7.3.x through 7.3.3.");

  script_tag(name:"solution", value:"Update to version 7.2.7, 7.3.3 or later.");

  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2022-26305");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2022-26306");

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

if (version_in_range(version: version, test_version: "7.2.0", test_version2: "7.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.3.0", test_version2: "7.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

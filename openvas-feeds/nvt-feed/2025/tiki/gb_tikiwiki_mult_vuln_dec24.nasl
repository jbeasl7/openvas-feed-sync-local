# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171309");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-18 20:55:57 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-47918", "CVE-2024-47919", "CVE-2024-47920");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tiki Wiki CMS Groupware < 28.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-47918: Improper neutralization of script-related HTML tags in a Web Page (Basic XSS)

  - CVE-2024-47919: OS Command Injection

  - CVE-2024-47920: Improper neutralization of input during Web Page generation (XSS)");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware prior to version 28.0.");

  script_tag(name:"solution", value:"Update to version 28.0 or later.");

  script_xref(name:"URL", value:"https://www.gov.il/en/departments/dynamiccollectors/cve_advisories_listing?skip=0&AffectedProducts=tiki");

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

if (version_is_less(version: version, test_version: "28.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "28.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

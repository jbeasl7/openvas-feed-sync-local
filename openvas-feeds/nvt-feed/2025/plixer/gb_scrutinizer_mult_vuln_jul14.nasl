# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:plixer:scrutinizer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125151");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-25 14:11:43 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2014-4976", "CVE-2014-4977");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plixer / Dell SonicWALL Scrutinizer 11.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_plixer_dell_scrutinizer_http_detect.nasl");
  script_mandatory_keys("plixer_dell/scrutinizer/http/detected");

  script_tag(name:"summary", value:"Plixer / Dell SonicWALL Scrutinizer is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2014-4976: Dell SonicWall Scrutinizer allows remote authenticated users to change user
  passwords via the user ID in the savePrefs parameter in a change password request to cgi-bin/admin.cgi

  - CVE-2014-4977: Multiple SQL injection vulnerabilities in Dell SonicWall Scrutinizer allow remote
  authenticated users to execute arbitrary SQL commands via the selectedUserGroup parameter in a
  create new user request to cgi-bin/admin.cgi or the user_id parameter in the changeUnit function,
  methodDetail parameter in the methodDetail function, or xcNetworkDetail parameter in the
  xcNetworkDetail function in d4d/exporters.php.");

  script_tag(name:"affected", value:"Plixer / Dell SonicWALL Scrutinizer version 11.0.1.");

  script_tag(name:"solution", value:"Update to version 11.5.2 or later.");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/127429");

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

if (version_is_equal(version: version, test_version: "11.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

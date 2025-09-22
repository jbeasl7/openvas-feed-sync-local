# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:plixer:scrutinizer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125152");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-25 14:33:27 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-24 19:19:45 +0000 (Fri, 24 Jan 2020)");

  script_cve_id("CVE-2012-1258", "CVE-2012-1259", "CVE-2012-1260", "CVE-2012-1261");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plixer / Dell SonicWALL Scrutinizer < 9.0.1.19899 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_plixer_dell_scrutinizer_http_detect.nasl");
  script_mandatory_keys("plixer_dell/scrutinizer/http/detected");

  script_tag(name:"summary", value:"Plixer / Dell SonicWALL Scrutinizer is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2012-1258: An issue was discovered in cgi-bin/userprefs.cgi which does not validate user
  permissions, and allow remote attackers to add user accounts with administrator privileges via the
  newuser, pwd, and selectedUserGroup parameters

  - CVE-2012-1259: Multiple SQL injection vulnerabilities allow remote attackers to execute
  arbitrary SQL commands via the addip parameter to cgi-bin/scrut_fa_exclusions.cgi,
  getPermissionsAndPreferences parameter to cgi-bin/login.cgi, or possibly certain parameters to
  d4d/alarms.php as demonstrated by the search_str parameter

  - CVE-2012-1260: XSS vulnerability in cgi-bin/scrut_fa_exclusions.cgi allows remote attackers to
  inject arbitrary web script or HTML via the standalone parameter

  - CVE-2012-1261: XSS vulnerability in cgi-bin/userprefs.cgi allows remote attackers to inject
  arbitrary web script or HTML via the newUser parameter.

  NOTE: this might not be a vulnerability, since an administrator might already have the privileges
  to create arbitrary script.");

  script_tag(name:"affected", value:"Plixer / Dell SonicWALL Scrutinizer versions prior to 9.0.1.19899.");

  script_tag(name:"solution", value:"Update to version 9.0.1.19899 or later.");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/111791");

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

if (version_is_less(version: version, test_version: "9.0.1.19899")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.1.19899", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

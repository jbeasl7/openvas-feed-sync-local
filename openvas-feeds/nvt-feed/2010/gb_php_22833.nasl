# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100604");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2007-1378", "CVE-2007-1379");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 4.4.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities in the Ovrimos
  extension.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2007-1378: The ovrimos_longreadlen function in the Ovrimos extension allows
  context-dependent attackers to write to arbitrary memory locations via the result_id and length
  arguments.

  - CVE-2007-1379: The ovrimos_close function in the Ovrimos extension can trigger efree of an
  arbitrary address");

  script_tag(name:"impact", value:"Successful exploits may allow an attacker to execute arbitrary
  code in the context of the affected application. Failed exploits would likely crash PHP.

  Note: For this vulnerability to occur, the non-maintained 'Ovrimos SQL Server Extension' must have
  been compiled into the targeted PHP implementation.");

  script_tag(name:"affected", value:"PHP versions prior to 4.4.5 with a compiled 'Ovrimos SQL
  Server Extension' are vulnerable to this issue.");

  script_tag(name:"solution", value:"Update to PHP version 4.4.5 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20181007042659/http://www.securityfocus.com/bid/22833");
  script_xref(name:"URL", value:"http://www.php-security.org/MOPB/MOPB-13-2007.html");

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

if (version_is_less(version: version, test_version: "4.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

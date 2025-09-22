# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805689");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2015-07-23 13:10:57 +0530 (Thu, 23 Jul 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-9705", "CVE-2015-0273");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.4.38, 5.5.x < 5.5.22, 5.6.x < 5.6.6 Multiple RCE Vulnerabilities (Jul 2015) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Multiple use-after-free vulnerabilities in 'ext/date/php_date.c' script.

  - Heap-based buffer overflow in the 'enchant_broker_request_dict' function in
  'ext/enchant/enchant.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote attackers to
  execute arbitrary code via some crafted dimensions.");

  script_tag(name:"affected", value:"PHP prior to version 5.4.38, 5.5.x prior to 5.5.22 and 5.6.x
  prior to 5.6.6.");

  script_tag(name:"solution", value:"Update to version 5.4.38, 5.5.22, 5.6.6 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73031");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72701");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1194730");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-04/msg00002.html");

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

if (version_is_less(version: version, test_version: "5.4.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5.0", test_version2: "5.5.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.6.0", test_version2: "5.6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

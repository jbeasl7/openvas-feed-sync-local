# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108871");
  script_version("2025-05-02T15:41:40+0000");
  script_tag(name:"last_modification", value:"2025-05-02 15:41:40 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2020-08-17 06:44:26 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-0421", "CVE-2011-0708", "CVE-2011-1092", "CVE-2011-1153",
                "CVE-2011-1464", "CVE-2011-1466", "CVE-2011-1467", "CVE-2011-1468",
                "CVE-2011-1469", "CVE-2011-1470");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.3.x < 5.3.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PHP 5.3.x before version 5.3.6.");

  script_tag(name:"solution", value:"Update to version 5.3.6 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46365");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46786");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46854");

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

if (version_in_range(version: version, test_version: "5.3", test_version2: "5.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

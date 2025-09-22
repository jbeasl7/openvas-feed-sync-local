# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103486");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2012-05-08 11:25:16 +0200 (Tue, 08 May 2012)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2012-1172");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Directory Traversal Vulnerability (Apr 2012)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a directory traversal vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote attackers can use specially crafted requests with
  directory- traversal sequences ('../') to retrieve, corrupt or upload arbitrary files in the
  context of the application.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to retrieve,
  corrupt or upload arbitrary files at arbitrary locations that could aid in further attacks.");

  script_tag(name:"affected", value:"PHP versions 5.x prior to 5.3.11 and 5.4.0 only.");

  script_tag(name:"solution", value:"Update to version 5.3.11, 5.4.1 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20120513003105/http://www.securityfocus.com/bid/53403");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=799187");
  script_xref(name:"URL", value:"http://www.php.net/archive/2012.php#id2012-04-26-1");

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

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

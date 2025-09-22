# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108872");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-08-17 08:47:19 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-24 22:06:00 +0000 (Mon, 24 Feb 2020)");

  script_cve_id("CVE-2014-3622");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.6.x < 5.6.1 Use-after-free Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to a use-after-free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a use-after-free vulnerability in the add_post_var function
  in the Posthandler component of PHP.");

  script_tag(name:"impact", value:"The flaw might allow remote attackers to execute arbitrary code by
  leveraging a third-party filter extension that accesses a certain ksep value.");

  script_tag(name:"affected", value:"PHP versions 5.6.x prior to 5.6.1.");

  script_tag(name:"solution", value:"Update to version 5.6.1 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-5.php#5.6.1");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=68088");

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

if (version =~ "^5\.6\." && version_is_less(version: version, test_version: "5.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

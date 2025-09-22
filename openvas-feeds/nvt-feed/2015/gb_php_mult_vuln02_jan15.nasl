# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805413");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2015-01-07 12:28:06 +0530 (Wed, 07 Jan 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-9426");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.6.5 Multiple Vulnerabilities (Jan 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A free operation on a stack-based character array is performed
  by the apprentice_load function in libmagic/apprentice.c in the Fileinfo component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"PHP versions prior to 5.6.5.");

  script_tag(name:"solution", value:"Update to version 5.6.5 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=68665");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1031480");

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

if (version_is_less_equal(version: version, test_version: "5.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902356");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-1148");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.7 Use After Free Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to an use after free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error occurs due to passing the same variable multiple
  times to the 'substr_replace()' function, which makes the PHP to use the same pointer in three
  variables inside the function.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code in the context of a web server. Failed attempts will likely result in denial of
  service conditions.");

  script_tag(name:"affected", value:"PHP version 5.3.6 and prior.");

  script_tag(name:"solution", value:"Update to version 5.3.7 or later.");

  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=54238");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46843");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/03/13/3");

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

if (version_is_less_equal(version: version, test_version: "5.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

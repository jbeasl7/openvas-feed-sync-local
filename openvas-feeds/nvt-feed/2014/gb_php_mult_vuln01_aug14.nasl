# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804820");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2014-08-25 20:30:05 +0530 (Mon, 25 Aug 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-3587", "CVE-2014-3597", "CVE-2014-5120");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.4.x < 5.4.32, 5.5.x < 5.5.15 Multiple Vulnerabilities (Aug 2014)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-3597: Multiple overflow conditions in the 'php_parserr' function within
  ext/standard/dns.c script.

  - CVE-2014-3587: Integer overflow in the 'cdf_read_property_info' function in cdf.c within the
  Fileinfo component.

  - CVE-2014-5120: An error in the '_php_image_output_ctx' function within ext/gd/gd_ctx.c script as
  NULL bytes in paths to various image handling functions are not stripped.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  overwrite arbitrary files, conduct denial of service attacks or potentially execute arbitrary
  code.");

  script_tag(name:"affected", value:"PHP version 5.4.x prior to 5.4.32 and 5.5.x prior to
  5.5.16.");

  script_tag(name:"solution", value:"Update to version 5.4.32, 5.5.16 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69322");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69325");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69375");
  script_xref(name:"URL", value:"http://secunia.com/advisories/59709");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57349");

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

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5.0", test_version2: "5.5.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

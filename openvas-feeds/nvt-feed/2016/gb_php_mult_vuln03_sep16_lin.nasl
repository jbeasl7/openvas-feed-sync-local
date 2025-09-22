# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809317");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-09-12 18:19:30 +0530 (Mon, 12 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-04 01:29:00 +0000 (Fri, 04 May 2018)");

  script_cve_id("CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416",
                "CVE-2016-7417", "CVE-2016-7418");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.6.26, 7.x < 7.0.11 Multiple Vulnerabilities (Sep 2016) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Use-after-free vulnerability in the 'wddx_stack_destroy' function in 'ext/wddx/wddx.c' script.

  - Improper verification of a BIT field has the UNSIGNED_FLAG flag in
  'ext/mysqlnd/mysqlnd_wireprotocol.c' script.

  - The ZIP signature-verification feature does not ensure that the uncompressed_filesize field is
  large enough.

  - The script 'ext/spl/spl_array.c' proceeds with SplArray unserialization without validating a
  return value and data type.

  - The script 'ext/intl/msgformat/msgformat_format.c' does not properly restrict the locale length
  provided to the Locale class in the ICU library.

  - An error in the php_wddx_push_element function in ext/wddx/wddx.c.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote attackers to
  cause a denial of service, or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"PHP prior to version 5.6.26 and 7.x prior to 7.0.11 on
  Linux.");

  script_tag(name:"solution", value:"Update to version 5.6.26, 7.0.11 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93006");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93008");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93007");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93011");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");

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

if (version_is_less(version: version, test_version: "5.6.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

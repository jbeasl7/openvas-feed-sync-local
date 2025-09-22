# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808634");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-07-29 11:54:44 +0530 (Fri, 29 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_cve_id("CVE-2016-5399", "CVE-2016-6207", "CVE-2016-6288", "CVE-2016-6289",
                "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6292", "CVE-2016-6294",
                "CVE-2016-6295", "CVE-2016-6296", "CVE-2016-6297");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.5.38, 5.6.x < 5.6.24, 7.0.x < 7.0.9 Multiple Vulnerabilities (Jul 2016) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Integer overflow in the 'php_stream_zip_opener' function in 'ext/zip/zip_stream.c'

  - Integer signedness error in the 'simplestring_addn' function in 'simplestring.c' in xmlrpc-epi

  - 'ext/snmp/snmp.c' improperly interacts with the unserialize implementation and garbage
  collection

  - The 'locale_accept_from_http' function in 'ext/intl/locale/locale_methods.c' does not properly
  restrict calls to the ICU 'uloc_acceptLanguageFromHTTP' function

  - Error in the 'exif_process_user_comment' function of 'ext/exif/exif.c'

  - Error in the 'exif_process_IFD_in_MAKERNOTE' function of 'ext/exif/exif.c'

  - 'ext/session/session.c' does not properly maintain a certain hash data structure

  - Integer overflow in the 'virtual_file_ex' function of 'TSRM/tsrm_virtual_cwd.c'

  - Error in the 'php_url_parse_ex' function of 'ext/standard/url.c'

  - Integer overflow error within _gdContributionsAlloc()

  - Inadequate error handling in bzread()");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow attackers to
  cause a denial of service obtain sensitive information from process memory, or possibly have
  unspecified other impact.");

  script_tag(name:"affected", value:"PHP prior to version 5.5.38, 5.6.x prior to 5.6.24 and 7.x
  prior to 7.0.9.");

  script_tag(name:"solution", value:"Update to version 5.5.38, 5.6.24, 7.0.9 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92111");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92074");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92097");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92073");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92115");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92094");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92095");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92099");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/24/2");

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

if (version_is_less(version: version, test_version: "5.5.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

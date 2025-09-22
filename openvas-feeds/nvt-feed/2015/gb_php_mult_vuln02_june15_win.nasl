# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805655");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2015-06-16 18:45:49 +0530 (Tue, 16 Jun 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025",
                "CVE-2015-4026");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.4.41, 5.5.x < 5.5.25, 5.6.x < 5.6.9 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Algorithmic complexity vulnerability in the 'multipart_buffer_headers' function in
  main/rfc1867.c script in PHP.

  - 'pcntl_exec' implementation in PHP truncates a pathname upon encountering a \x00 character.

  - Integer overflow in the 'ftp_genlist' function in ext/ftp/ftp.c script in PHP.

  - The 'phar_parse_tarfile' function in ext/phar/tar.c script in PHP does not verify that the first
  character of a filename is different from the \0 character.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  cause a denial of service, bypass intended extension restrictions and access and execute files or
  directories with unexpected names via crafted dimensions and remote FTP servers to execute
  arbitrary code.");

  script_tag(name:"affected", value:"PHP prior to version 5.4.41, 5.5.x prior to 5.5.25 and 5.6.x
  prior to 5.6.9.");

  script_tag(name:"solution", value:"Update to version 5.4.41, 5.5.25, 5.6.9 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74700");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=69085");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/06/01/4");

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

if (version_is_less(version: version, test_version: "5.4.41")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.41", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5.0", test_version_up: "5.5.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

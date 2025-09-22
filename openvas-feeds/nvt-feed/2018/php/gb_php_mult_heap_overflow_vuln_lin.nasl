# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813901");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-08-07 13:28:46 +0530 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 13:30:00 +0000 (Fri, 08 Mar 2019)");

  script_cve_id("CVE-2018-14851", "CVE-2018-14883", "CVE-2018-15132");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Heap Buffer Overflow and Information Disclosure Vulnerabilities (Aug 2018) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple heap buffer overflow and information
  disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-14851: exif_process_IFD_in_MAKERNOTE function in exif.c file suffers from improper
  validation against crafted JPEG files.

  - CVE-2018-14883: exif_thumbnail_extract function in exif.c file suffers from improper validation
  of length of 'ImageInfo->Thumbnail.offset + ImageInfo->Thumbnail.size'

  - CVE-2018-15132: linkinfo function on windows doesn't implement openbasedir check.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause heap
  overflow, denial of service and disclose sensitive information.");

  script_tag(name:"affected", value:"PHP prior to version 5.6.37, 7.x prior to 7.0.31, 7.1.x prior
  to 7.1.20 and 7.2.x prior to 7.2.8.");

  script_tag(name:"solution", value:"Update to version 5.6.37, 7.0.31, 7.1.20 or 7.2.8 or
  later.");

  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2018-14851");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76557");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76423");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76459");

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

if (version_is_less(version: version, test_version: "5.6.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.1.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2.0", test_version_up: "7.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

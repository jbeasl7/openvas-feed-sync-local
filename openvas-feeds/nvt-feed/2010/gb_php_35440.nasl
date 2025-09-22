# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100581");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2009-2687");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.2.10 JPEG Image Processing DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability in the
  exif_read_data() function.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to cause denial
  of service conditions in applications that use the vulnerable function.");

  script_tag(name:"affected", value:"PHP prior to version 5.2.10.");

  script_tag(name:"solution", value:"Update to version 5.2.10 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35440");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_10.php");
  script_xref(name:"URL", value:"http://lists.debian.org/debian-security-announce/2009/msg00263.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-08/0339.html");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100072880");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.2.0", test_version_up: "5.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801123");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2009-3546");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.2.x < 5.2.12, 5.3.0 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The '_gdGetColors' function in gd_gd.c fails to check certain
  colorsTotal structure member, whicn can be exploited to cause buffer overflow or buffer over-read
  attacks via a crafted GD file.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to potentially
  compromise a vulnerable system.");

  script_tag(name:"affected", value:"PHP version 5.2.x through 5.2.11 and 5.3.0.");

  script_tag(name:"solution", value:"Update to version 5.2.12, 5.3.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37080/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36712");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2930");
  script_xref(name:"URL", value:"http://marc.info/?l=oss-security&m=125562113503923&w=2");

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

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

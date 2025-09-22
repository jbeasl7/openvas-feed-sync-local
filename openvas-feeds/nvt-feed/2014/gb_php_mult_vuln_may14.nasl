# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804291");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2014-05-09 09:47:32 +0530 (Fri, 09 May 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-7226", "CVE-2013-7327", "CVE-2013-7328", "CVE-2014-2020");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.5.x < 5.5.9 Multiple Vulnerabilities (May 2014)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2013-7226: Integer overflow in the 'gdImageCrop' function within ext/gd/gd.c script.

  - CVE-2013-7327: Improper data types check as using string or array data type in place of a
  numeric data type within ext/gd/gd.c script.

  - CVE-2013-7328: Multiple integer signedness errors in the 'gdImageCrop' function within
  ext/gd/gd.c script.

  - CVE-2014-2020: NULL pointer dereference errors related to the 'imagecrop' function
  implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  denial of service, gain sensitive information and have some other unspecified impacts.");

  script_tag(name:"affected", value:"PHP version 5.5.x prior to 5.5.9.");

  script_tag(name:"solution", value:"Update to version 5.5.9 or later.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1065108");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65533");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65656");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65668");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65676");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.5.0", test_version_up: "5.5.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

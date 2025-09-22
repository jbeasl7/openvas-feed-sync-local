# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834084");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2023-27331", "CVE-2023-27330", "CVE-2023-27329");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-20 07:04:40 +0530 (Thu, 20 Jun 2024)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (June-3 2024)");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2023-27331: An out-of-bounds read information disclosure vulnerability

  - CVE-2023-27330: An use-after-free remote code execution vulnerability

  - CVE-2023-27329: An use-after-free remote code execution vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute remote code.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 12.x through
  12.1.0.15250, 11.x through 11.2.4.53774, 10.1.10.37854 and prior on
  Windows.");

  script_tag(name:"solution", value:"Update to version 10.1.11 or 11.2.5 or
  12.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"10.1.11")) {
  fix = "10.1.11";
}

if(version_in_range(version:vers, test_version:"11.0", test_version2:"11.2.4.53774")) {
  fix = "11.2.5";
}

if(version_in_range(version:vers, test_version:"12.0", test_version2:"12.1.0.15250") ) {
  fix = "12.1.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);


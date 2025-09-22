# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834433");
  script_version("2024-10-22T05:05:39+0000");
  script_cve_id("CVE-2024-7722", "CVE-2024-7723", "CVE-2024-7724", "CVE-2024-7725");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-18 15:45:29 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-08-22 16:12:56 +0530 (Thu, 22 Aug 2024)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (Aug 2024) - Windows");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-7722: use-after-free information disclosure vulnerability

  - CVE-2024-7723: use-after-free remote code rxecution vulnerability

  - CVE-2024-7724: use-after-free remote code rxecution vulnerability

  - CVE-2024-7725: use-after-free remote code rxecution vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute remote code and disclose information.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 2024.x through
  2024.2.2.25170, 2023.x through 2023.3.0.23028, 13.x through 13.1.2.22442,
  12.x through 12.1.7.15526, 11.2.10.53951 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 13.1.3 or 2024.2.3 or
  later.");

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

if(version_is_less_equal(version:vers, test_version:"11.2.10.53951") ||
   version_in_range(version:vers, test_version:"12.0", test_version2:"12.1.7.15526") ||
   version_in_range(version:vers, test_version:"13.0", test_version2:"13.1.2.22442") ||
   version_in_range(version:vers, test_version:"2023", test_version2:"2023.3.0.23028" ||
   version_in_range(version:vers, test_version:"2024", test_version2:"2024.2.2.25170"))) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"13.1.3 or 2024.2.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);


# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832967");
  script_version("2024-06-24T05:05:34+0000");
  script_cve_id("CVE-2024-25575", "CVE-2024-25648", "CVE-2024-25938");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-24 05:05:34 +0000 (Mon, 24 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-30 15:15:52 +0000 (Tue, 30 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-05-02 14:53:56 +0530 (Thu, 02 May 2024)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (June-1 2024)");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-25575: A type confusion vulnerability

  - CVE-2024-25648: A use-after-free vulnerability

  - CVE-2024-25938: A use-after-free vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 2024.1.0.23997,
  2023.x through 2023.3.0.23028, 13.x through 13.0.1.21693, 12.x through
  12.1.4.15400, 11.2.8.53842 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 2024.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"https://www.foxit.com/support/security-bulletins.html#content-2024");
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

if(version_is_less(version:vers, test_version:"11.2.8.53842") ||
   version_in_range(version:vers, test_version:"12.0", test_version2:"12.1.4.15400") ||
   version_in_range(version:vers, test_version:"13.0", test_version2:"13.0.1.21693") ||
   version_in_range(version:vers, test_version:"2023", test_version2:"2023.3.0.23028") ||
   version_is_equal(version:vers, test_version:"2024.1.0.23997")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2024.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);


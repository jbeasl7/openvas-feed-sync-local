# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834081");
  script_version("2025-08-08T05:44:56+0000");
  script_cve_id("CVE-2024-25858", "CVE-2024-30322", "CVE-2024-30324", "CVE-2024-30325",
                "CVE-2024-30326", "CVE-2024-30327", "CVE-2024-30328", "CVE-2024-30329",
                "CVE-2024-30330", "CVE-2024-30331", "CVE-2024-30332", "CVE-2024-30333",
                "CVE-2024-30334", "CVE-2024-30335", "CVE-2024-30336", "CVE-2024-30337",
                "CVE-2024-30338", "CVE-2024-30339", "CVE-2024-30340", "CVE-2024-30342",
                "CVE-2024-30343", "CVE-2024-30344", "CVE-2024-30345", "CVE-2024-30346",
                "CVE-2024-30347", "CVE-2024-30350", "CVE-2024-30351", "CVE-2024-30352",
                "CVE-2024-30353", "CVE-2024-30355", "CVE-2024-30357", "CVE-2024-30348",
                "CVE-2024-30358", "CVE-2024-30349", "CVE-2024-30363", "CVE-2024-30364",
                "CVE-2024-30367", "CVE-2024-30371", "CVE-2024-32488", "CVE-2024-30356",
                "CVE-2024-30323", "CVE-2024-30360", "CVE-2024-30361", "CVE-2024-30362",
                "CVE-2024-30341", "CVE-2024-30354", "CVE-2024-30359", "CVE-2024-30365",
                "CVE-2024-30366");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-07 19:00:08 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-06-20 07:04:40 +0530 (Thu, 20 Jun 2024)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (Jun 2024)");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-25858: A code execution error via JavaScript

  - CVE-2024-30322: use-after-free remote code rxecution vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute remote code, escalate privileges and disclose information.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 2023.x through
  2023.3.0.23028, 13.x through 13.0.1.21693, 12.x through 12.1.4.15400, 11.x
  through 11.2.8.53842, 10.1.12.37872 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 2024.1 or later.");

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

if(version_is_less_equal(version:vers, test_version:"10.1.12.37872") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.2.8.53842") ||
   version_in_range(version:vers, test_version:"12.0", test_version2:"12.1.4.15400") ||
   version_in_range(version:vers, test_version:"13.0", test_version2:"13.0.1.21693") ||
   version_in_range(version:vers, test_version:"2023", test_version2:"2023.3.0.23028")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2024.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);


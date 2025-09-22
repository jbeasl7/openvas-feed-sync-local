# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834075");
  script_version("2025-03-07T15:40:19+0000");
  script_cve_id("CVE-2024-29072");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-07 15:40:19 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-28 14:15:12 +0000 (Tue, 28 May 2024)");
  script_tag(name:"creation_date", value:"2024-06-19 11:04:13 +0530 (Wed, 19 Jun 2024)");
  script_name("Foxit PhantomPDF Privilege Escalation Vulnerability (Jun 2024)");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to a privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper
  certification validation of the updater executable before executing it.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 2024.x through
  2024.2.1.25153, 2023.x through 2023.3.0.23028, 13.x through 13.1.1.22432,
  12.x through 12.1.6.15509, 11.2.9.53938 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 2024.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"11.2.9.53938") ||
   version_in_range(version:vers, test_version:"12.0", test_version2:"12.1.6.15509") ||
   version_in_range(version:vers, test_version:"13.0", test_version2:"13.1.1.22432") ||
   version_in_range(version:vers, test_version:"2023", test_version2:"2023.3.0.23028") ||
   version_in_range(version:vers, test_version:"2024", test_version2:"2024.2.1.25153")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2024.2.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);


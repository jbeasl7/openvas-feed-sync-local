# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826900");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2022-43310");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-15 14:44:00 +0000 (Tue, 15 Nov 2022)");
  script_tag(name:"creation_date", value:"2023-01-30 17:08:32 +0530 (Mon, 30 Jan 2023)");
  script_name("Foxit Reader Privilege Escalation Vulnerability (Jan 2023)");

  script_tag(name:"summary", value:"Foxit Reader is prone to a privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an uncontrolled
  search path element privilege escalation vulnerability attack due to not
  specifying an absolute path when searching for a DLL library.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers
  to execute a malicious DLL file.");

  script_tag(name:"affected", value:"Foxit Reader version 11.1.140.51553 and
  earlier on Windows.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader 11.2.118.51569
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/pdf-reader");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pdfVer = infos["version"];
pdfPath = infos["location"];

if(version_is_less(version:pdfVer, test_version:"11.2.118.51569"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"11.2.118.51569", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(99);

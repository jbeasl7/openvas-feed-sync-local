# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826762");
  script_version("2024-01-22T05:07:31+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-21579", "CVE-2023-21581", "CVE-2023-21585", "CVE-2023-21586",
                "CVE-2023-21604", "CVE-2023-21605", "CVE-2023-21606", "CVE-2023-21607",
                "CVE-2023-21608", "CVE-2023-21609", "CVE-2023-21610", "CVE-2023-21611",
                "CVE-2023-21612", "CVE-2023-21613", "CVE-2023-21614", "CVE-2023-22240",
                "CVE-2023-22241", "CVE-2023-22242");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-27 19:12:00 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 09:52:21 +0530 (Wed, 11 Jan 2023)");
  script_name("Adobe Reader DC Continuous Security Update (APSB23-01) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple stack-based buffer overflow errors.

  - Violation of Secure Design Principles.

  - An integer overflow or wraparound error.

  - Multiple out-of-bounds read or write errors.

  - A NULL Pointer dereference error.

  - An use after free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges, execute arbitrary code, cause denial of service and
  memory leak on an affected system.");

  script_tag(name:"affected", value:"Adobe Reader DC (Continuous) versions
  22.003.20282 and earlier on Windows.");

  script_tag(name:"solution", value:"Update Adobe Reader DC (Continuous)
  to version 22.003.20310 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Continuous/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"22.003.20310"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"22.003.20310", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

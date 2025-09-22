# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832834");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-20726", "CVE-2024-20727", "CVE-2024-20728", "CVE-2024-20729",
                "CVE-2024-20730", "CVE-2024-20731", "CVE-2024-20733", "CVE-2024-20734",
                "CVE-2024-20735", "CVE-2024-20736", "CVE-2024-20747", "CVE-2024-20748",
                "CVE-2024-20749", "CVE-2024-30301", "CVE-2024-30302", "CVE-2024-30303",
                "CVE-2024-30304", "CVE-2024-30305", "CVE-2024-30306", "CVE-2024-20765");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 13:15:47 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-15 15:29:41 +0530 (Thu, 15 Feb 2024)");
  script_name("Adobe Acrobat DC Continuous Security Update (APSB24-07) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC (Continuous) is prone to
  multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple Use After Free errors.

  - Multiple Out-of-bounds Read errors.

  - Multiple Out-of-bounds Write errors.

  - An Integer Overflow or Wraparound.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, conduct denial of service and memory leak on an
  affected system.");

  script_tag(name:"affected", value:"Adobe Acrobat DC (Continuous) versions
  23.008.20470 and earlier on Windows.");

  script_tag(name:"solution", value:"Update to version 23.008.20533 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb24-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_cont_detect_macosx.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Continuous/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"23.008.20470")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"23.008.20533", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

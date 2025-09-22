# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812101");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-10947", "CVE-2017-10948", "CVE-2017-10946");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-11-10 12:34:48 +0530 (Fri, 10 Nov 2017)");
  script_name("Foxit Reader Multiple Arbitrary Code Execution and DoS Vulnerabilities (Nov 2017) - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to arbitrary code execution and denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the lack of
  validating the existence of an object prior to performing operations
  on the object.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or can cause denial of service condition.");

  script_tag(name:"affected", value:"Foxit Reader version 8.2.1.6871 and prior.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version 8.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.us-cert.gov/ncas/bulletins/SB17-310");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
foxitVer = infos["version"];
foxPath = infos["location"];

if(version_is_less_equal(version:foxitVer, test_version:"8.2.1.6871"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"8.3", install_path:foxPath);
  security_message(data:report);
  exit(0);
}

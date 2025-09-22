# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833929");
  script_version("2024-06-14T05:05:48+0000");
  script_cve_id("CVE-2024-30284", "CVE-2024-30310", "CVE-2024-34094", "CVE-2024-34095",
                "CVE-2024-34096", "CVE-2024-34097", "CVE-2024-34098", "CVE-2024-34099",
                "CVE-2024-34100", "CVE-2024-30311", "CVE-2024-30312", "CVE-2024-34101",
                "CVE-2024-30279", "CVE-2024-30280");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-15 10:15:14 +0000 (Wed, 15 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-16 17:08:30 +0530 (Thu, 16 May 2024)");
  script_name("Adobe Acrobat Reader DC Continuous Security Update (APSB24-07) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat Reader DC (Continuous) is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-30310: out-of-bounds write error

  - CVE-2024-30311: out-of-bounds read error

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code, cause memory leak.");

  script_tag(name:"affected", value:"Adobe Reader DC (Continuous) versions
  24.002.20736 and earlier on Windows.");

  script_tag(name:"solution", value:"Update to version 24.002.20759 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb24-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Continuous/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"24.002.20736")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.002.20759", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

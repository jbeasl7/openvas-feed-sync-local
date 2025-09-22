# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821185");
  script_version("2023-10-18T05:05:17+0000");
  script_cve_id("CVE-2022-34230", "CVE-2022-34229", "CVE-2022-34228", "CVE-2022-34227",
                "CVE-2022-34226", "CVE-2022-34225", "CVE-2022-34224", "CVE-2022-34223",
                "CVE-2022-34222", "CVE-2022-34237", "CVE-2022-34238", "CVE-2022-34239",
                "CVE-2022-34236", "CVE-2022-34221", "CVE-2022-34234", "CVE-2022-34220",
                "CVE-2022-34219", "CVE-2022-34217", "CVE-2022-34216", "CVE-2022-34233",
                "CVE-2022-34215", "CVE-2022-34232", "CVE-2022-35669");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-21 17:57:00 +0000 (Thu, 21 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 09:06:05 +0530 (Wed, 13 Jul 2022)");
  script_name("Adobe Reader 2017 Security Update (APSB22-32) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Access of Uninitialized Pointer.

  - out-of-bounds read errors.

  - Access of Resource Using Incompatible Type.

  - out-of-bounds write errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and leak memory on the target system.");

  script_tag(name:"affected", value:"Adobe Reader 2017 versions 17.012.30227
  and earlier on Mac OS X.");

  script_tag(name:"solution", value:"Update Adobe Reader 2017 to version
  17.012.30249 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-32.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.012.30227")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.012.30249", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

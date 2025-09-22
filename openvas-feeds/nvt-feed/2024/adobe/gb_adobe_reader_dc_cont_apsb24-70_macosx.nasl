# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834604");
  script_version("2024-10-04T15:39:55+0000");
  script_cve_id("CVE-2024-41869", "CVE-2024-45112");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-04 15:39:55 +0000 (Fri, 04 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-13 09:15:13 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-17 11:04:04 +0530 (Tue, 17 Sep 2024)");
  script_name("Adobe Acrobat Reader DC Continuous Security Update (APSB24-70) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Acrobat Reader DC (Continuous) is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-41869: use after free error

  - CVE-2024-45112: access of resource using incompatible type (type confusion vulnerability)");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Reader DC (Continuous) versions
  24.002.21005 and earlier on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 24.003.20112 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb24-70.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_cont_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Continuous/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"24.002.21005")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.003.20112", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813090");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2018-10120");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-04-17 12:10:45 +0530 (Tue, 17 Apr 2018)");
  script_name("LibreOffice 'SwCTBWrapper::Read' Function Memory Corruption Vulnerability - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as 'SwCTBWrapper::Read'
  function in sw/source/filter/ww8/ww8toolbar.cxx in LibreOffice does not
  validate a customizations index.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (heap-based buffer overflow with write
  access) or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"LibreOffice before 5.4.6.1 and 6.x before
  6.0.2.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version 5.4.6.1 or
  6.0.2.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=6173");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.4.6.1")) {
  fix = "5.4.6.1";
}

else if(vers =~ "^6\." && version_is_less(version:vers, test_version:"6.0.2.1")) {
  fix = "6.0.2.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

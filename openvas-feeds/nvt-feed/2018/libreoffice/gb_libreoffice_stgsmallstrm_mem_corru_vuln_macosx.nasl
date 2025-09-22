# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813089");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2018-10119");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 21:21:00 +0000 (Tue, 05 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-04-17 14:02:53 +0530 (Tue, 17 Apr 2018)");
  script_name("LibreOffice 'StgSmallStrm' Function Memory Corruption Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"LibreOffice is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as 'sot/source/sdstor/stgstrms.cxx'
  in LibreOffice uses an incorrect integer data type in the StgSmallStrm class.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (use-after-free with write access) or
  possibly have unspecified other impact.");

  script_tag(name:"affected", value:"LibreOffice before 5.4.5.1 and 6.x before
  6.0.1.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version 5.4.5.1 or
  6.0.1.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=5747");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.4.5.1")){
  fix = "5.4.5.1";
}

else if(vers =~ "^6\." && version_is_less(version:vers, test_version:"6.0.1.1")){
  fix = "6.0.1.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

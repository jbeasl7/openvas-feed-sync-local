# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811584");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-8358");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-20 01:29:00 +0000 (Sat, 20 May 2017)");
  script_tag(name:"creation_date", value:"2017-08-18 12:11:47 +0530 (Fri, 18 Aug 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("LibreOffice 'ReadJPEG' Function Heap Buffer Overflow Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"LibreOffice is prone to a heap buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a heap-based buffer
  overflow error related to the 'ReadJPEG' function in
  'vcl/source/filter/jpeg/jpegc.cxx' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to execute arbitrary code within the context of the affected
  application. Failed exploit attempts will result in a denial-of-service
  condition.");

  script_tag(name:"affected", value:"LibreOffice versions 5.2.6 and earlier
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version
  5.2.7 or later.
  Note: 5.2 series end of life is June 4, 2017");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://github.com/LibreOffice/core/commit/6e6e54f944a5ebb49e9110bdeff844d00a96c56c");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98395");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!libreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:libreVer, test_version:"5.2.7"))
{
  report = report_fixed_ver(installed_version:libreVer, fixed_version:"Upgrade to 5.2.7 or later");
  security_message(data:report);
  exit(0);
}

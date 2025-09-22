# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808575");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-4324");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-07-12 11:29:23 +0530 (Tue, 12 Jul 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("LibreOffice Use-after-free Vulnerability (Jul 2016) - Mac OS X");

  script_tag(name:"summary", value:"LibreOffice is prone to a use after free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation
  of RTF parser validity.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"LibreOffice version before 5.1.4 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version
  5.1.4 or 5.2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.libreoffice.org/about-us/security/advisories/cve-2016-4324");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91499");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:libreVer, test_version:"5.1.4"))
{
  report = report_fixed_ver(installed_version:libreVer, fixed_version:"5.1.4 or 5.2.0");
  security_message(data:report);
  exit(0);
}

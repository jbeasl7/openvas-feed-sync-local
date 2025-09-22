# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901224");
  script_version("2025-03-05T05:38:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-3896");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 17:26:01 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-10-09 12:56:06 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Silverlight Information Disclosure Vulnerability (2890788) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-087.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Download and install the hotfixes from the referenced advisory.");

  script_tag(name:"insight", value:"Flaw is caused when Silverlight improperly handles certain objects in
  memory.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5 on Mac OS X.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain potentially
  sensitive information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2890788");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62793");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-087");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_ms_silverlight_detect_macosx.nasl");
  script_mandatory_keys("MS/Silverlight/MacOSX/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!msl_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(msl_ver=~ "^5\.")
{
  if(version_in_range(version:msl_ver, test_version:"5.0", test_version2:"5.1.20912.0"))
  {
    report = report_fixed_ver(installed_version:msl_ver, vulnerable_range:"5.0 - 5.1.20912.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

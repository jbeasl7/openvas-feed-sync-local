# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805555");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2015-1715");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-05-13 13:46:39 +0530 (Wed, 13 May 2015)");
  script_name("Microsoft Silverlight Elevation of Privilege Vulnerability (3058985) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-049.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the Silverlight improperly
  allows applications that are intended to run at a low integrity level (very
  limited permissions) to be executed at a medium integrity level (permissions of
  the current user) or higher.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code with the same or higher level of permissions as the
  currently logged on user.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5 on Mac OS X.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3058985");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74503");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-049");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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
  if(version_in_range(version:msl_ver, test_version:"5.0", test_version2:"5.1.40415"))
  {
    report = report_fixed_ver(installed_version:msl_ver, vulnerable_range:"5.0 - 5.1.40415");
    security_message(port: 0, data: report);
    exit(0);
  }
}

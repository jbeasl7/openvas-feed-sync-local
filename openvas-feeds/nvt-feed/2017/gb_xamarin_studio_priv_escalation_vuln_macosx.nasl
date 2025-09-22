# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xamarin:studio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811708");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2017-8665");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-08-17 16:37:16 +0530 (Thu, 17 Aug 2017)");
  script_name("Xamarin Studio Privilege Escalation Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Xamarin Studio is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  'Xamarin.iOS' update component of the application which improperly handles
  directories and binaries.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to escalate privileges and run arbitrary code as root. An attacker
  could then install programs, or view, change, or delete data or create new
  accounts that have full user rights.");

  script_tag(name:"affected", value:"Xamarin Studio for Mac version 6.2.1
  (build 3) and version 6.3 (build 863).");

  script_tag(name:"solution", value:"Upgrade to latest version of Visual Studio
  for Mac which has replaced Xamarin Studio.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4037359");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100308");
  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20170403");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_xamarin_studio_detect_macosx.nasl");
  script_mandatory_keys("Xamarin/Studio/MacOSX/Version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/visualstudio/mac/");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!xarVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(xarVer == "6.2.1.3" || xarVer == "6.3.863")
{
  report = report_fixed_ver(installed_version:xarVer, fixed_version:"Latest Visual Studio for Mac");
  security_message(data:report);
  exit(0);
}
exit(0);

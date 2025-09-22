# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812208");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-11791", "CVE-2017-11834", "CVE-2017-11843", "CVE-2017-11846",
                "CVE-2017-11848", "CVE-2017-11855", "CVE-2017-11858", "CVE-2017-11869");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-01 14:12:00 +0000 (Fri, 01 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-11-15 10:47:54 +0530 (Wed, 15 Nov 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (KB4047206)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security updates KB4047206.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Scripting engine does not properly handle objects in memory.

  - Internet Explorer improperly handles page content.

  - Internet Explorer improperly accesses objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain information to further compromise the user's system, execute arbitrary
  code in the context of the current user, detect the navigation of the user
  leaving a maliciously crafted page.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4047206");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^9\."){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer){
  exit(0);
}

if(hotfix_check_sp(win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"9.0.8112.21073"))
  {
    report = report_fixed_ver( file_checked:iePath + "\Mshtml.dll",
                               file_version:iedllVer, vulnerable_range:"Less than 9.0.8112.21073" );
    security_message(data:report);
    exit(0);
  }
}
exit(0);

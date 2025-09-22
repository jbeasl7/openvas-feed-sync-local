# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812336");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-11907", "CVE-2017-11912", "CVE-2017-11886", "CVE-2017-11887",
                "CVE-2017-11890", "CVE-2017-11894", "CVE-2017-11895", "CVE-2017-11901",
                "CVE-2017-11903", "CVE-2017-11906", "CVE-2017-11913", "CVE-2017-11919",
                "CVE-2017-11930");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-25 19:13:00 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-12-13 10:40:44 +0530 (Wed, 13 Dec 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (KB4052978)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security updates KB4052978.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple errors in Internet Explorer which improperly accesses objects in
    memory.

  - Multiple errors when Internet Explorer improperly handles objects in memory.

  - Multiple errors exist in the way the scripting engine handles objects in
    memory in Microsoft browsers.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user, gain the same
  user rights as the current user and obtain sensitive information to further
  compromise the user's system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x, 10.x and 11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4052978");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102092");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102063");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102082");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102046");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102091");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102058");
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

if(hotfix_check_sp(win2008:3, win2008x64:3, win7:2, win7x64:2, win2008r2:2, win2012:1,  win2012R2:1,
                   win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^(9|10|11)"){
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

##Server 2008
if(hotfix_check_sp(win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"9.0.8112.21084")){
    Vulnerable_range = "Less than 9.0.8112.21084";
  }
}

# Win 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"10.0.9200.22314")){
    Vulnerable_range = "Less than 10.0.9200.22314";
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"11.0.9600.18860")){
     Vulnerable_range = "Less than 11.0.9600.18860";
  }
}

if(Vulnerable_range)
{
  report = report_fixed_ver(file_checked:iePath + "\Mshtml.dll",
                            file_version:iedllVer, vulnerable_range:Vulnerable_range);
  security_message(data:report);
  exit(0);
}
exit(0);

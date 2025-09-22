# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811117");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-0267", "CVE-2017-0268", "CVE-2017-0269", "CVE-2017-0270",
                "CVE-2017-0271", "CVE-2017-0272", "CVE-2017-0273", "CVE-2017-0274",
                "CVE-2017-0275", "CVE-2017-0276", "CVE-2017-0277", "CVE-2017-0278",
                "CVE-2017-0279", "CVE-2017-0280");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-10 12:51:18 +0530 (Wed, 10 May 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SMB Multiple Vulnerabilities (KB4018466)");

  script_tag(name:"summary", value:"This host is missing a critical/important
  security update according to Microsoft KB4018466");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the error in
  the way Microsoft Server Message Block 1.0 (SMBv1) server handles certain
  requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the affected system to stop responding until it is manually
  restarted. Also successful exploitation will allow attacker to get sensitive
  data and execute arbitrary code in context of current user.");

  script_tag(name:"affected", value:"- Microsoft Windows XP SP2 x64

  - Microsoft Windows XP SP3 x86

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-gb/help/4018466");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98259");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98261");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98263");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98264");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98265");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98260");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98266");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98267");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98272");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98273");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025687");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win2008:3, winVistax64:3, win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

if(!asVer = fetch_file_version(sysPath:sysPath, file_name:"drivers\srv.sys")){
  exit(0);
}

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{

  if(version_is_less(version:asVer, test_version:"6.0.6002.19765"))
  {
    Vulnerable_range = "Less than 6.0.6002.19765";
    VULN = TRUE ;
  }

  else if(version_in_range(version:asVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.24088"))
  {
    Vulnerable_range = "6.0.6002.22000 - 6.0.6002.24088";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:asVer, test_version:"5.1.2600.7238"))
  {
    Vulnerable_range = "Less than 5.1.2600.7238";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2003:3, win2003x64:3, xpx64:3) > 0)
{
  if(version_is_less(version:asVer, test_version:"5.2.3790.6051"))
  {
    Vulnerable_range = "Less than 5.2.3790.6051";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\drivers\srv.sys" + '\n' +
           'File version:     ' + asVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);

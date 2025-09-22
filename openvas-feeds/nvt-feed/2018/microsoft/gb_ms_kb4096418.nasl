# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813188");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-0765", "CVE-2018-1039");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-05-09 14:47:38 +0530 (Wed, 09 May 2018)");
  script_name("Microsoft .NET Framework Security Feature Bypass And DoS Vulnerabilities (KB4096418)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4096418");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - An error when .NET and .NET Core improperly process XML documents.

  - An error in .Net Framework which could allow an attacker to bypass
    Device Guard.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to cause a denial of service and circumvent a User Mode Code
  Integrity (UMCI) policy on the machine.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4096418");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full";
if(!registry_key_exists(key:key)){
  exit(0);
}

version = registry_get_sz(key:key, item:"Version");
if(!version){
  exit(0);
}

if(((hotfix_check_sp(win7:2, win7x64:2,  win2008r2:2) > 0) && (version =~ "^4\.(7|6)"))||
   ((hotfix_check_sp(win2008:3, win2008x64:3) > 0) && (version =~ "^4\.6")))
{
  dotPath = registry_get_sz(key:key, item:"InstallPath");
  if(dotPath && "Microsoft.NET" >< dotPath)
  {
    dotPath = dotPath + "SetupCache\v" + version;
    dllVer = fetch_file_version(sysPath:dotPath, file_name:"sqmapi.dll");
    if(dllVer && version_is_less(version:dllVer, test_version:"6.2.9200.16384"))
    {
      report = report_fixed_ver(file_checked:dotPath + "\sqmapi.dll",
                                file_version:dllVer, vulnerable_range:"Less than 6.2.9200.16384");
      security_message(data:report);
      exit(0);
    }
  }
}
exit(99);

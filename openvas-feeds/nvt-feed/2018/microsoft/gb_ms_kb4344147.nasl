# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813759");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-8360", "CVE-2018-8202");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-08-15 09:11:10 +0530 (Wed, 15 Aug 2018)");
  script_name("Microsoft .NET Framework Multiple Vulnerabilities (KB4344147)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4344147");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - When .NET Framework is used in high-load/high-density network connections
    where content from one stream can blend into another stream.

  - An error in how .NET Framework activates COM objects.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to access information in multi-tenant environments and elevate their privilege
  level.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 4.5.2 for Microsoft Windows 8.1 and Microsoft Windows Server 2012 R2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4344147");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  dotPath = registry_get_sz(key:key + item, item:"Path");
  if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
  {
    sysdllVer = fetch_file_version(sysPath:dotPath, file_name:"mscorlib.dll");
    if(!sysdllVer|| sysdllVer !~ "^4\."){
      continue;
    }

    if(version_in_range(version:sysdllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36459"))
    {
      report = report_fixed_ver(file_checked:dotPath + "mscorlib.dll",
                                file_version:sysdllVer, vulnerable_range:"4.0.30319.30000 - 4.0.30319.36459");
      security_message(data:report);
      exit(0);
    }
  }
}
exit(99);

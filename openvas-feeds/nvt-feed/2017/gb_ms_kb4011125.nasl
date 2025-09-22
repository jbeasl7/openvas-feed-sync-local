# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811822");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8696");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 18:47:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-13 12:26:27 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Office Word Viewer Remote Code Execution Vulnerability (KB4011125)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4011125");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to due to the way Windows
  Uniscribe handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited this vulnerability to take control
  of the affected system.");

  script_tag(name:"affected", value:"Microsoft Office Word Viewer.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011125");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100780");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/WordView/Version");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(!wordviewVer){
  exit(0);
}

wordviewPath = get_kb_item("SMB/Office/WordView/Install/Path");
if(!wordviewPath){
  wordviewPath = "Unable to fetch the install path";
}

offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"CommonFilesDir");
if(offPath)
{
  offPath += "\Microsoft Shared\OFFICE11";
  dllVer = fetch_file_version(sysPath:offPath, file_name:"usp10.dll");
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"1.626.6002.24173"))
    {
      report = 'File checked:     ' + offPath + "\Usp10.dll" + '\n' +
               'File version:     ' + dllVer + '\n' +
               'Vulnerable range: Less than 1.626.6002.24173 \n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
exit(0);

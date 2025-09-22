# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811818");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-8631", "CVE-2017-8632");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 15:45:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-13 10:13:27 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Office Compatibility Pack Service Pack 3 Multiple Vulnerabilities (KB4011064)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011064");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the Microsoft Office software
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited the vulnerability to use a specially
  crafted file to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011064");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100751");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100734");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/ComptPack/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!path){
  exit(0);
}

cmpPckVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmpPckVer && cmpPckVer =~ "^12\.")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer && xlcnvVer =~ "^12\.")
  {
    offpath = path + "\Microsoft Office\Office12";
    sysVer = fetch_file_version(sysPath:offpath, file_name:"xl12cnv.exe");
    if(sysVer && sysVer =~ "^12\.")
    {
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6776.4999"))
      {
        report = 'File checked:      ' + offpath + "\xl12cnv.exe" + '\n' +
                 'File version:      ' + sysVer  + '\n' +
                 'Vulnerable range:  12.0 - 12.0.6776.4999' + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

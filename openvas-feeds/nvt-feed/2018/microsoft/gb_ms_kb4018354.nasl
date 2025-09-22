# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813134");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-0950");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-04-11 14:42:32 +0530 (Wed, 11 Apr 2018)");
  script_name("Microsoft Office Compatibility Pack Service Pack 3 Information Disclosure Vulnerability (KB4018354)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4018354");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error when Office
  renders Rich Text Format (RTF) email messages containing OLE  objects when
  a message is opened or previewed.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4018354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103642");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/ComptPack/Version", "SMB/Office/WordCnv/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

cmpPckVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmpPckVer && cmpPckVer =~ "^12\.")
{
  os_arch = get_kb_item("SMB/Windows/Arch");
  if("x86" >< os_arch){
    key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
  }
  else if("x64" >< os_arch){
    key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                          "SOFTWARE\Microsoft\Windows\CurrentVersion");
  }

  foreach key(key_list)
  {
    msPath = registry_get_sz(key:key, item:"ProgramFilesDir");
    if(msPath)
    {
      wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
      if(wordcnvVer && wordcnvVer =~ "^12\.")
      {
        offpath = msPath + "\Microsoft Office\Office12";
        {
          sysVer = fetch_file_version(sysPath:offpath, file_name:"wordcnv.dll");
          if(sysVer && sysVer =~ "^12\.0")
          {
            if(version_is_less(version:sysVer, test_version:"12.0.6787.5000"))
            {
              report = report_fixed_ver(file_checked:offpath + "\wordcnv.dll",
                                        file_version:sysVer, vulnerable_range:"12.0 - 12.0.6787.4999");
              security_message(data:report);
              exit(0);
            }
          }
        }
      }
    }
  }
}
exit(0);

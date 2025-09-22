# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902958");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-0079");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-03-13 13:42:19 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft Filter Pack Remote Code Execution Vulnerability (2801261)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553501");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58369");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028276");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-023");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Filter Pack Service Pack 1 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by a type confusion error when handling Tree objects
  and can be exploited via a specially crafted Visio file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-023.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  filterName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Microsoft Filter Pack" >< filterName)
  {
    filterVer = fetch_file_version(sysPath:path,
                file_name:"\Microsoft Shared\Filters\ONIFILTER.DLL");

    if(filterVer && filterVer =~ "^14\.")
    {
      if(version_in_range(version:filterVer, test_version:"14.0", test_version2:"14.0.6134.4999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

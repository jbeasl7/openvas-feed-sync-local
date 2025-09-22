# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901069");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0102");
  script_name("Microsoft Office Project Remote Code Execution Vulnerability (967183)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/961083");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/961079");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/961082");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3439");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-074");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an affected
  application or execute arbitrary code by tricking a user into opening a
  specially crafted document.");

  script_tag(name:"affected", value:"- Microsoft Project 2002 Service Pack 1

  - Microsoft Project 2000 Service Release 1

  - Microsoft Office Project 2003 Service Pack 3");

  script_tag(name:"insight", value:"This issue is due to application not properly validating resource allocations
  when opening Project files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-074.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# MS09-074 Hotfix check
if((hotfix_missing(name:"961082") == 0) || (hotfix_missing(name:"961083") == 0)
   || (hotfix_missing(name:"961079") == 0)){
   exit(0);
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!dllPath){
  exit(0);
}

foreach path (make_list("\MS Project", "\Microsoft Office Project",
                        "\Microsoft Office Project 10", "\Microsoft Office Project 9",
                        "\Microsoft Office Project 11")) {

  filepath = dllPath + "\Common Files\Microsoft Shared" + path + "\ATLCONV.DLL";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:filepath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:filepath);
  dllVer = GetVer(file:file, share:share);
  if(!dllVer) continue;

  if(version_in_range(version:dllVer, test_version:"9.0", test_version2:"9.0.2001.1108") ||
     version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.2108.2215") ||
     version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.3.2008.1716")){
    report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"9.0 - 9.0.2001.1108 / 10.0 - 10.0.2108.2215 / 11.0 - 11.3.2008.1716", file_checked:filepath);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(0);

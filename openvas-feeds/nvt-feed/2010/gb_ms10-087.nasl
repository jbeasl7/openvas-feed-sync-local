# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901166");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-11-10 14:58:25 +0100 (Wed, 10 Nov 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:38:35 +0000 (Tue, 16 Jul 2024)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-3333", "CVE-2010-3334", "CVE-2010-3335",
                "CVE-2010-3336", "CVE-2010-3337");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2423930)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"- Microsoft Office XP Service Pack 3

  - Microsoft Office 2003 Service Pack 3

  - Microsoft Office 2007 Service Pack 2

  - Microsoft Office 2010");

  script_tag(name:"insight", value:"Multiple flaws are caused by,

  - a stack overflow error when processing malformed Rich Text Format data.

  - a memory corruption error when processing Office Art Drawing records in
    Office files.

  - a memory corruption error when handling drawing exceptions.

  - a memory corruption error when handling SPID data in Office documents.

  - an error when loading certain libraries from the current working directory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-087.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2923");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42628");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44656");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44659");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44660");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-087");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

function FileVer (file, path)
{
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:path);
  if(share =~ "[a-z]\$")
    share = toupper(share);
  file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:path + file);
  ver = GetVer(file:file, share:share);
  return ver;
}

officeVer = get_kb_item("MS/Office/Ver");

## MS Office XP, 2003, 2007, 2010
if(officeVer && officeVer =~ "^1[0124]\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(! path) {
    exit(0);
  }

  foreach ver (make_list("OFFICE10", "OFFICE11", "OFFICE12", "OFFICE14"))
  {
    offPath = path + "\Microsoft Shared\" + ver;
    dllVer = FileVer(file:"\Mso.dll", path:offPath);
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.6866.9")   ||
         version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8328.9")   ||
         version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6545.5003")||
         version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.5128.4999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900809");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-03 06:30:10 +0200 (Mon, 03 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0901", "CVE-2009-2493", "CVE-2009-2495");
  script_name("Microsoft Visual Studio ATL Remote Code Execution Vulnerability (969706)");
  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx/kb/969706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35828");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35830");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35832");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-035");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Microsoft/VisualStudio_or_VisualStudio.Net/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code which may
  result in memory corruption on the affected system.");

  script_tag(name:"affected", value:"- Microsoft Visual Studio 2005 SP 1 and prior

  - Microsoft Visual Studio 2008 SP 1 and prior

  - Microsoft Visual Studio .NET 2003 SP 1 and prior");

  script_tag(name:"insight", value:"- An error in the ATL headers when handling persisted streams can be exploited
  to cause VariantClear function to be called on a VARIANT that has not been
  correctly initialised via a specially crafted web page.

  - An error in the ATL headers when handling object instantiation from data
  streams may allow bypassing of security policies such as kill-bits in
  Internet Explorer if a control or component uses OleLoadFromStream function in an unsafe manner.

  - An error in ATL may result in a string being read without terminating NULL
  bytes, which can be exploited to disclose memory contents beyond the end of the string.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-035.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# MS09-035 Hotfix check
if((hotfix_missing(name:"971089") == 0)||(hotfix_missing(name:"971090") == 0)||
   (hotfix_missing(name:"971091") == 0)||(hotfix_missing(name:"971092") == 0)){
  exit(0);
}

visStudVer = get_kb_item("Microsoft/VisualStudio/Ver");

if(visStudVer && visStudVer =~ "^[89]\.")
{
  studioPath = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\8.0", item:"InstallDir");
  if(studioPath)
    atlPath = studioPath - "\Common7\IDE" + "VC\redist\x86\Microsoft.VC80.ATL\atl80.dll";
  else
  {
    studioPath = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\9.0", item:"InstallDir");
    if(studioPath){
      atlPath = studioPath - "\Common7\IDE" + "VC\redist\x86\Microsoft.VC90.ATL\atl90.dll";
    }
  }

  if(atlPath)
  {
    share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:atlPath);
    file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:atlPath);
    atlVer = GetVer(file:file, share:share);

    if(atlVer && atlVer =~ "^[89]\.")
    {
      #          VC++ 2008 version 9.0.20000.0 < 9.0.21022.218 and
      #          VC++ 2008 SP1 version 9.0.30000.0 < 9.0.30729.4148
      if(version_in_range(version:atlVer, test_version:"8.0", test_version2:"8.0.50727.4052") ||
         version_in_range(version:atlVer, test_version:"9.0.20000.0", test_version2:"9.0.21022.217") ||
         version_in_range(version:atlVer, test_version:"9.0.30000.0", test_version2:"9.0.30729.4147"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

visStudNetVer = get_kb_item("Microsoft/VisualStudio.Net/Ver");

if(visStudNetVer && visStudNetVer =~ "^7\.")
{
  vsnfile1 = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
  if(!vsnfile1){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:vsnfile1);
  vsnfile2 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:vsnfile1 + "\atl71.dll");
  vsnetVer = GetVer(file:vsnfile2, share:share);

  if(vsnetVer && vsnetVer =~ "^7\.")
  {
    if(version_in_range(version:vsnetVer, test_version:"7.0", test_version2:"7.10.6100.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

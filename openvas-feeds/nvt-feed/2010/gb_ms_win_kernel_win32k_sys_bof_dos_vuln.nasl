# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902256");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-2739");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows win32k.sys Driver 'CreateDIBPalette()' BOF Vulnerability");
  script_xref(name:"URL", value:"http://www.ragestorm.net/blogs/?p=255");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2029");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash an affected
system or potentially execute arbitrary code with kernel privileges.");
  script_tag(name:"affected", value:"- Microsoft Windows 7

  - Microsoft Windows XP SP3 and prior

  - Microsoft Windows Vista SP 2 and prior

  - Microsoft Windows Server 2008 SP 2 and prior

  - Microsoft Windows Server 2003 SP 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to a buffer overflow error in the
'CreateDIBPalette()' function within the kernel-mode device driver 'Win32k.sys',
when using the 'biClrUsed' member value of a 'BITMAPINFOHEADER' structure as a
counter while retrieving Bitmap data from the clipboard.");
  script_tag(name:"solution", value:"Apply the latest updates");
  script_tag(name:"summary", value:"This host is prone to buffer ovreflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/en/us/default.aspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

exit(0); ##plugin may results to FP

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");

if(sysPath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Win32k.sys");

  sysVer = GetVer(file:file, share:share);
  if(!isnull(sysVer))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                         item:"PathName");
if(sysPath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:sysPath + "\system32\Win32k.sys");
  sysVer = GetVer(file:file, share:share);
  if(!isnull(sysVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

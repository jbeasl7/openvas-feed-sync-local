# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801333");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1734", "CVE-2010-1735");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Windows Kernel 'win32k.sys' Multiple DOS Vulnerabilities");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2010/Apr/207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39630");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39631");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/510886/100/0/threaded");
  script_xref(name:"URL", value:"http://vigilance.fr/vulnerability/Windows-denials-of-service-of-win32k-sys-9607");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause Denial of
service.");
  script_tag(name:"affected", value:"- Microsoft Windows XP SP3 and prior

  - Microsoft Windows 2000 SP4 and prior

  - Microsoft Windows Server 2003 SP2 and prior");
  script_tag(name:"insight", value:"The flaws are due to:

  - error in the 'SfnLOGONNOTIFY()' function in 'win32k.sys' when handling
   window messages. This can be exploited to cause a kernel crash by sending
   a specially crafted '4Ch' message to the 'DDEMLEvent' window.

  - error in the 'SfnINSTRING()' function in 'win32k.sys' when handling
   window messages. This can be exploited to cause a kernel crash by
   sending a specially crafted '18Dh' message to the 'DDEMLEvent' window.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Windows XP/2000/2003 is prone to multiple Denial Of Service
  vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Win32k.sys");
sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

if(version_in_range(version:sysVer, test_version:"5.0", test_version2:"5.0.2195.6708") ||
   version_in_range(version:sysVer, test_version:"5.1", test_version2:"5.1.2600.5863") ||
   version_in_range(version:sysVer, test_version:"5.2", test_version2:"5.2.3790.4571")){
 security_message( port: 0, data: "The target host was found to be vulnerable" );
}

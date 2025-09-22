# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800687");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-3020");
  script_name("Microsoft Windows Server 2003 OpenType Font Engine DoS Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9417");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36029");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52403");
  script_xref(name:"URL", value:"http://www.microsoft.com/en-us/download/details.aspx?id=1185");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow attakers to cause denial of
  service via a specially-crafted file containing EOT font embedded in the
  document thus crashing the operating system.");

  script_tag(name:"affected", value:"Microsoft Windows 2003 Service Pack 2 and prior.");

  script_tag(name:"insight", value:"The vulnerability is due to an error in 'win32k.sys' when
  processing Embedded OpenType font.");

  script_tag(name:"solution", value:"Vendor has released patch to fix the issue, please see the references
  for more information.");

  script_tag(name:"summary", value:"Windows Server 2003 operating system is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3) <= 0){
  exit(0);
}

SP = get_kb_item("SMB/Win2003/ServicePack");
if("Service Pack 1" >< SP || "Service Pack 2" >< SP)
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                         item:"Install Path");
  if(sysPath != NULL)
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
    file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:sysPath + "\Win32k.sys");
    sysVer = GetVer(file:file, share:share);
    if(sysVer)
    {
      if(version_is_less_equal(version:sysVer, test_version:"5.2.3790.4497")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}

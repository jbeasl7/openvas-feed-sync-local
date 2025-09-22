# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802886");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-12 14:18:37 +0530 (Thu, 12 Jul 2012)");
  script_name("Microsoft Sidebar and Gadgets Remote Code Execution Vulnerability (2719662)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2719662");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2013/2719662");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code as the logged-on user.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior");
  script_tag(name:"insight", value:"Windows Sidebar when running insecure Gadgets allows an attacker to
  run arbitrary code.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"Microsoft Windows Sidebar and Gadgets is prone to a remote code execution (RCE) vulnerability.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2) <= 0){
  exit(0);
}

key1 = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\sidebar.exe";
if(registry_key_exists(key:key1))
{
  key2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar";
  if(registry_key_exists(key:key2))
  {
    sidebarVal = registry_get_dword(key:key2, item:"TurnOffSidebar");
    if(!sidebarVal && !(int(sidebarVal) == 1))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
  else
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

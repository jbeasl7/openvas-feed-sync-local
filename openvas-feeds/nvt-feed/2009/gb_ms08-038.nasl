# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900445");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-02-02 05:02:24 +0100 (Mon, 02 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0243", "CVE-2008-0951");
  script_name("Microsoft Autorun Arbitrary Code Execution Vulnerability (08-038)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the affected Windows system and can gain sensitive information or
  can make the system resources completely unavailable.");

  script_tag(name:"affected", value:"- Microsoft Windows 2K SP4 / XP SP2 / 2003 SP2 and prior

  - Microsoft Windows Vista Service Pack 1 and prior

  - Microsoft Windows Server 2008 Service Pack 1 and prior");

  script_tag(name:"insight", value:"MS Windows OSes are not able to enforce the 'Autorun' and 'NoDriveTypeAutoRun'
  registry values. Allows physically proximate attackers to execute malicious
  code by inserting CD-ROM media, inserting DVD media, connecting a USB device,
  connecting a Firewire device, by mapping a network drive, by clicking on an
  icon under My Computer\Devices with Removable Storage and AutoPlay dialog
  related to the Autorun.inf file.");

  script_tag(name:"solution", value:"Apply the security patch (KB950582).");

  script_tag(name:"summary", value:"Windows Operating System is prone to Autorun Arbitrary Code Execution Vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/results.aspx?pocId=7&freetext=KB950582&DisplayLang=en");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28360");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/953252");
  script_xref(name:"URL", value:"http://isc.sans.org/diary.html?storyid=5695");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA09-020A.html");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

if(hotfix_missing(name:"950582") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  shellVer = fetch_file_version(sysPath:sysPath, file_name:"shell32.dll");
  if(shellVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_is_less(version:shellVer, test_version:"5.0.3900.7155")){
        report = report_fixed_ver(installed_version:shellVer, fixed_version:"5.0.3900.7155", install_path:sysPath);
        security_message(port: 0, data: report);
      }
      exit(0);
    }

    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:shellVer, test_version:"6.0.2900.3402")){
          report = report_fixed_ver(installed_version:shellVer, fixed_version:"6.0.2900.3402", install_path:sysPath);
          security_message(port: 0, data: report);
        }
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        if(version_is_less(version:shellVer, test_version:"6.0.2900.5622")){
          report = report_fixed_ver(installed_version:shellVer, fixed_version:"6.0.2900.5622", install_path:sysPath);
          security_message(port: 0, data: report);
        }
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:shellVer, test_version:"6.0.3790.3158")){
           report = report_fixed_ver(installed_version:shellVer, fixed_version:"6.0.3790.3158", install_path:sysPath);
           security_message(port: 0, data: report);
        }
        exit(0);
      }
      else if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:shellVer, test_version:"6.0.3790.4315")){
            report = report_fixed_ver(installed_version:shellVer, fixed_version:"6.0.3790.4315", install_path:sysPath);
            security_message(port: 0, data: report);
        }
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"shell32.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"6.0.6001.18062")){
          report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18062", install_path:sysPath);
          security_message(port: 0, data: report);
        }
         exit(0);
      }
    }

    else if(hotfix_check_sp(win2008:2) > 0)
    {
      SP = get_kb_item("SMB/Win2008/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"6.0.6001.18062")){
          report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18062", install_path:sysPath);
          security_message(port: 0, data: report);
        }
         exit(0);
      }
    }
  }
}


# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801701");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-01-10 14:22:58 +0100 (Mon, 10 Jan 2011)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 16:54:54 +0000 (Wed, 14 Feb 2024)");
  script_cve_id("CVE-2008-0087");
  script_name("Microsoft Windows DNS Client Service Response Spoofing Vulnerability (945553)");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Apr/1019802.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28553");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-020");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to spoof DNS replies,
  allowing them to redirect network traffic and to launch man-in-the-middle attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 2K/XP/2003/Vista.");

  script_tag(name:"insight", value:"The flaws are due to the Windows DNS client using predictable
  transaction IDs in outgoing queries and can be exploited to poison the DNS
  cache when the transaction ID is guessed.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-020.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:2) <= 0){
  exit(0);
}

if(hotfix_missing(name:"945553") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"dnsapi.dll");
if(dllVer)
{
  if(hotfix_check_sp(win2k:5) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"5.0.2195.7151")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.0.2195.7151", install_path:sysPath);
      security_message(port: 0, data: report);
    }
  }

  else if(hotfix_check_sp(xp:4) > 0)
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(version_is_less(version:dllVer, test_version:"5.1.2600.3316")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.1.2600.3316", install_path:sysPath);
        security_message(port: 0, data: report);
      }
    }
  }

  else if(hotfix_check_sp(win2003:3) > 0)
  {
    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 1" >< SP)
    {
      if(version_is_less(version:dllVer, test_version:"5.2.3790.3092")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.2.3790.3092", install_path:sysPath);
        security_message(port: 0, data: report);
      }
    }
    else if("Service Pack 2" >< SP)
    {
      if(version_is_less(version:dllVer, test_version:"5.2.3790.4238")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.2.3790.4238", install_path:sysPath);
        security_message(port: 0, data: report);
      }
    }
    else security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  else if(hotfix_check_sp(winVista:2) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6000.16615")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6000.16615", install_path:sysPath);
        security_message(port: 0, data: report);
    }
    exit(0);
  }
}

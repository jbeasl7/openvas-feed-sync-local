# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801479");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-25 08:29:59 +0100 (Thu, 25 Nov 2010)");
  script_cve_id("CVE-2010-0239", "CVE-2010-0240", "CVE-2010-0241",
                "CVE-2010-0242");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows TCP/IP Could Allow Remote Code Execution (974145)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0342");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38063");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38064");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-009");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code with system privileges. Failed exploit attempts will likely result in
  denial-of-service conditions.");
  script_tag(name:"affected", value:"- Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");
  script_tag(name:"insight", value:"The flaws are due to Windows TCP/IP stack,

  - not performing the appropriate level of bounds checking on specially crafted
    'ICMPv6' Router Advertisement packets.

  - fails to properly handle malformed Encapsulating Security Payloads (ESP) over
    UDP datagram fragments while running a custom network driver that splits the
    UDP header into multiple MDLs, which could be exploited by remote attackers
    to execute arbitrary code by sending specially crafted IP datagram fragments
    to a vulnerable system.

  - not performing the appropriate level of bounds checking on specially crafted
    ICMPv6 Route Information packets, which could be exploited by remote
    attackers to execute arbitrary code by sending specially crafted ICMPv6
    packets to a vulnerable system.

  - not properly handling TCP packets with a malformed selective acknowledgment
    (SACK) value.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-009.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win2008:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"974145") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\System32\drivers\tcpip.sys");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18377")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6001.18377");
      security_message(port: 0, data: report);
    }
      exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:sysVer, test_version:"6.0.6002.18160")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6002.18160");
      security_message(port: 0, data: report);
    }
      exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18377")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6001.18377");
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18160")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6002.18160");
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

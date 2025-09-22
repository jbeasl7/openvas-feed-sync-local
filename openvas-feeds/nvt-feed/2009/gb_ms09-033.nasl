# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900690");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-15 20:20:16 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1542");
  script_name("Microsoft Virtual PC/Server Privilege Escalation Vulnerability (969856)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code with
  escalated privileges on the guest operating system.");

  script_tag(name:"affected", value:"- Microsoft Virtual PC 2004 Service Pack 1 and prior

  - Microsoft Virtual PC 2007 Service Pack 1 and prior

  - Microsoft Virtual Server 2005 R2 Service Pack 1 and prior");

  script_tag(name:"insight", value:"The flaw is due to the application not properly validating required
  CPU privilege levels of certain machine instructions running within the guest
  operating system environment.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-033.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35601");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-033");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(registry_key_exists(key:"SOFTWARE\Microsoft\Virtual PC"))
{
  pcPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
  if(!pcPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:pcPath);
  pcfile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:pcPath + "\drivers\VMM.sys");

  pcVer = GetVer(file:pcfile, share:share);
  if(pcVer != NULL)
  {
    if(version_in_range(version:pcVer, test_version:"1.1.400.0", test_version2:"1.1.465.14")) {
      report = report_fixed_ver(installed_version:pcVer, vulnerable_range:"1.1.400.0 - 1.1.465.14");
      security_message(port: 0, data: report);
    }
    else if(version_in_range(version:pcVer, test_version:"1.1.500.0", test_version2:"1.1.597.0")) {
      report = report_fixed_ver(installed_version:pcVer, vulnerable_range:"1.1.500.0 - 1.1.597.0");
      security_message(port: 0, data: report);
    }
    else if(version_in_range(version:pcVer, test_version:"1.1.600.0", test_version2:"1.1.655.0")) {
      report = report_fixed_ver(installed_version:pcVer, vulnerable_range:"1.1.600.0 - 1.1.655.0");
      security_message(port: 0, data: report);
    }
    exit(0);
  }
}

if(registry_key_exists(key:"SOFTWARE\Microsoft\Virtual Server"))
{
  srvPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
  if(!srvPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:srvPath);
  srvfile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:srvPath + "\drivers\VMM.sys");
  srvVer = GetVer(file:srvfile, share:share);
  if(srvVer != NULL)
  {
    if(version_is_less(version:srvVer, test_version:"1.1.655.0")) {
      report = report_fixed_ver(installed_version:srvVer, fixed_version:"1.1.655.0");
      security_message(port: 0, data: report);
    }
  }
}

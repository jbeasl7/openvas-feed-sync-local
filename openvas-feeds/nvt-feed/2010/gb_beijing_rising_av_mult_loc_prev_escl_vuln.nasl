# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800178");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1591");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Rising Antivirus Drivers Multiple Local Privilege Escalation Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38335");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37951");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55869");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0218");
  script_xref(name:"URL", value:"http://www.ntinternals.org/ntiadv0902/ntiadv0902.html");
  script_xref(name:"URL", value:"http://www.ntinternals.org/ntiadv0805/ntiadv0805.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to corrupt kernel memory and
  execute arbitrary code on the system with kernel privileges.");

  script_tag(name:"affected", value:"Rising Antivirus 2008/2009/2010 on Windows.");

  script_tag(name:"insight", value:"The flaw exists due to error in the 'HookCont.sys', 'HookNtos.sys',
  'HOOKREG.sys', 'HookSys.sys' and 'RsNTGdi.sys' drivers while processing
  specially-crafted IOCTL requests.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Run SmartUpdate to Get the Fixed Drivers.");

  script_tag(name:"summary", value:"Rising Antivirus is prone to a local privilege escalation vulnerability.");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\rising\Rav";
risingDisplayName = registry_get_sz(key:key, item:"name");

if(risingDisplayName =~ "Rising AntiVirus Software (2008|2009|2010)")
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
  if(!sysPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\drivers\RsNTGdi.sys");
  risingDriverVer = GetVer(file:file, share:share);
  if(risingDriverVer)
  {
    if(version_in_range(version:risingDriverVer, test_version:"20.0", test_version2:"22.0.0.5")) {
      report = report_fixed_ver(installed_version:risingDriverVer, vulnerable_range:"20.0 - 22.0.0.5");
      security_message(port: 0, data: report);
    }
  }
}

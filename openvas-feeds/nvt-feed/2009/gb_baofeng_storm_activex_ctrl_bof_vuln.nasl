# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800570");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1612");
  script_name("BaoFeng Storm ActiveX Control Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34789");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34944");
  script_xref(name:"URL", value:"http://bbs.baofeng.com/read.php?tid=121630");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Attacker may exploit this issue to execute arbitrary script code and may cause
  denial of service.");

  script_tag(name:"affected", value:"BaoFeng Storm mps.dll version 3.9.4.27 and prior on Windows.");

  script_tag(name:"insight", value:"A boundary error in the MPS.StormPlayer.1 ActiveX control (mps.dll) while
  processing overly large argument passed to the 'OnBeforeVideoDownload()'
  method leads to buffer overflow.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest BaoFeng Storm version 3.9.05.10.");

  script_tag(name:"summary", value:"BaoFeng Storm ActiveX is prone to a buffer overflow vulnerability.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

stormPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                  "\Uninstall\Storm2", item:"DisplayIcon");
if(!stormPath){
  exit(0);
}

stormPath = stormPath - "Storm.exe" + "mps.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:stormPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:stormPath);

stormdllVer = GetVer(share:share, file:file);

if(stormdllVer != NULL)
{
  if(version_is_less_equal(version:stormdllVer, test_version:"3.9.4.27")){
    report = report_fixed_ver(installed_version:stormdllVer, vulnerable_range:"Less than or equal to 3.9.4.27", install_path:stormPath);
    security_message(port: 0, data: report);
  }
}

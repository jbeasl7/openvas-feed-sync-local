# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802371");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2011-5012");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-05 16:57:58 +0530 (Wed, 05 Jan 2011)");
  script_name("Attachmate Reflection FTP Client LIST Command Remote Heap Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71330");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50691");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1026340");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18119/");
  script_xref(name:"URL", value:"http://support.attachmate.com/techdocs/2288.html");
  script_xref(name:"URL", value:"http://support.attachmate.com/techdocs/2502.html");
  script_xref(name:"URL", value:"http://support.attachmate.com/techdocs/1708.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execution of arbitrary code.");

  script_tag(name:"affected", value:"Attachmate Reflection 2008

  Attachmate Reflection 2011 R1 before 15.3.2.569

  Attachmate Reflection 2011 R2 before 15.4.1.327

  Attachmate Reflection 14.1 SP1 before 14.1.1.206

  Attachmate Reflection Windows Client 7.2 SP1 before hotfix 7.2.1186");

  script_tag(name:"insight", value:"The flaw is due to boundary error in the Reflection FTP client in
  rftpcom.dll, which fails to process filenames within a directory listing.");

  script_tag(name:"summary", value:"Attachmate Reflection FTP Client is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Update to the latest version or apply the fix.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key))
  exit(0);

foreach item (registry_enum_keys(key:key)) {
  refName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Attachmate Reflection" >< refName)
  {
    refVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!isnull(refVer)) {
      if(version_in_range(version:refVer, test_version:"15.3", test_version2:"15.3.569.0") ||
         version_in_range(version:refVer, test_version:"15.4", test_version2:"15.4.327.0)") ||
         version_in_range(version:refVer, test_version:"7.2", test_version2:"7.2.1163") ||
         version_in_range(version:refVer, test_version:"14.1", test_version2:"14.1.1173"))
      {
        report = report_fixed_ver(installed_version:refVer, fixed_version:"See references");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

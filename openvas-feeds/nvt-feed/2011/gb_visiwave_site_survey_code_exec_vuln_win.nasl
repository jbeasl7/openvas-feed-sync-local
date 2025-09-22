# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802101");
  script_version("2025-09-18T05:38:39+0000");
  script_cve_id("CVE-2011-2386");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VisiWave Site Survey Arbitrary Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44636");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47948");
  script_xref(name:"URL", value:"http://www.visiwave.com/blog/index.php?/archives/4-Version-2.1.9-Released.html");
  script_xref(name:"URL", value:"http://www.stratsec.net/Research/Advisories/VisiWave-Site-Survey-Report-Trusted-Pointer-(SS-20");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"insight", value:"The flaw exists due to an error when processing report files and can be
  exploited to perform a virtual function call into an arbitrary memory location
  via a specially crafted 'Type' property.");

  script_tag(name:"solution", value:"Upgrade to VisiWave Site Survey version 2.1.9 or later.");

  script_tag(name:"summary", value:"VisiWave Site Survey is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"VisiWave Site Survey version prior to 2.1.9.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VisiWaveSiteSurvey";
if(!registry_key_exists(key:key))
  exit(0);

visiName = registry_get_sz(key:key, item:"DisplayName");
if("VisiWave Site Survey" >< visiName) {

  visiPath = registry_get_sz(key:key, item:"UninstallString");
  if(visiPath) {
    sysPath = eregmatch(string:visiPath, pattern:"^.*\\");
    fileName = eregmatch(string:visiPath, pattern:"[^\\]+$");
    visiVer = fetch_file_version(sysPath:sysPath[0], file_name:fileName[0]);
    if(visiVer) {
      if(version_is_less(version:visiVer, test_version:"2.1.9")) {
        report = report_fixed_ver(installed_version:visiVer, fixed_version:"2.1.9", file_checked:visiPath);
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);

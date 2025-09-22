# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901176");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0515");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Kingsoft Antivirus 'KisKrnl.sys' Driver Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42937");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45821");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64723");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15998/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"insight", value:"The flaw is due to an error when handling system service calls
  in the 'kisknl.sys' driver which can be exploited to cause a page fault error
  in the kernel and crash the system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Kingsoft Antivirus is prone to a denial of service vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to cause a denial
  of service condition.");

  script_tag(name:"affected", value:"Kingsoft Antivirus version 2011.1.13.89 and prior.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\Kingsoft"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Kingsoft Internet Security";
if(!registry_key_exists(key:key))
  exit(0);

ksantName = registry_get_sz(key:key, item:"DisplayName");
if("Kingsoft AntiVirus" >< ksantName) {

  ksantPath = registry_get_sz(key:key, item:"DisplayIcon");
  if(ksantPath) {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ksantPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ksantPath);

    ksantVer = GetVer(file:file, share:share);
    if(ksantVer) {
      if(version_is_less_equal(version:ksantVer, test_version:"2011.1.13.89")) {
        report = report_fixed_ver(installed_version:ksantVer, fixed_version:"None", file_checked:ksantPath);
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);

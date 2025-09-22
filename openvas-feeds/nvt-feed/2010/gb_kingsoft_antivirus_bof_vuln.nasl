# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902302");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3396");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Kingsoft Antivirus 'kavfm.sys' Buffer overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41393");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43173");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14987/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"insight", value:"The flaw exists due to an error in the 'kavfm.sys' driver when
  processing 'IOCTLs'. This can be exploited to corrupt kernel memory and potentially
  execute arbitrary code with escalated privileges via a specially crafted 0x80030004 IOCTL.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Kingsoft Antivirus is prone to a buffer overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code with SYSTEM-level privileges and completely compromise the
  affected computer. Failed exploit attempts will result in a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Kingsoft Antivirus 2010.04.26.648 and prior.");

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
      if(version_is_less_equal(version:ksantVer, test_version:"2010.04.26.648")) {
        report = report_fixed_ver(installed_version:ksantVer, fixed_version:"None", file_checked:file);
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);

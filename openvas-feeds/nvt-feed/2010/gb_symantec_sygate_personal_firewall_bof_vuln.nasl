# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901125");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-2305");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Symantec Sygate Personal Firewall ActiveX Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59408");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13834");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/10-050-sygate-personal-firewall-5-6-build-2808-activex/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary code on the system or cause the application to crash.");
  script_tag(name:"affected", value:"Symantec Sygate Personal Firewall 5.6 build 2808");
  script_tag(name:"insight", value:"The flaw is caused by an error in ActiveX control in SSHelper.dll
allows remote attackers to execute arbitrary code via a long third
argument to the SetRegString method.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Symantec Sygate Personal Firewall is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Sygate Technologies, Inc." +
                              "\Sygate Personal Firewall")){
    exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
    exit(0);
}


foreach item(registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Sygate Personal Firewall" >< name)
  {
    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ver != NULL)
    {
      if(version_is_equal(version:ver, test_version:"5.6.2808")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

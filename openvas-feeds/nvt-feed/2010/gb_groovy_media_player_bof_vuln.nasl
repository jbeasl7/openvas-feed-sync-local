# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801405");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2009-4931");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Groovy Media Player '.m3u' File Remote Stack Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/395659.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34621");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49965");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"insight", value:"The flaw is caused by improper bounds checking when parsing
malicious '.M3U' files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Groovy Media Player is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
denial of service or possibly execute arbitrary code.");
  script_tag(name:"affected", value:"Groovy Media Player 1.1.0");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Groovy Media Player")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
            "\Groovy Media Player";
if(!registry_key_exists(key:key)){
  exit(0);
}

gmpName = registry_get_sz(key:key, item:"DisplayName");

if("Groovy Media Player" >< gmpName)
{
  gmpVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(gmpVer != NULL)
  {
    if(version_is_equal(version:gmpVer, test_version:"1.1.0")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900404");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-5179");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Microsoft Windows RTCP Unspecified Remote DoS Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.voipshield.com/research-details.php?id=132");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32341");

  script_tag(name:"impact", value:"Successful exploitation will crash the application.");

  script_tag(name:"affected", value:"Microsoft Windows Live Messenger version 8.5.1302.1018 and prior.");

  script_tag(name:"insight", value:"The vulnerability is due to error in the 'RTCP' or
  'Real-time Transport Control Protocol' receiver report packet handling.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Live Messenger is prone to a remote Denial of Service vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

entries = registry_enum_keys(key:key);
if(entries == NULL){
  exit(0);
}

foreach item (entries)
{
  if("Windows Live Messenger" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    if((egrep(pattern:"^([0-7]\..*|8\.[0-4](\..*)?|8\.5(\.([0-9]?[0-9]?[0-9]" +
                      "|1[0-2]?[0-9]?[0-9]?|130[01])(\..*)?|\.1302)?(\.[0-9]" +
                      "?[0-9]?[0-9]|\.100[0-9]|\.101[0-8])?)?$",
              string:registry_get_sz(key:key + item, item:"DisplayVersion")))){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

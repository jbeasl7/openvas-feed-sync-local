# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802271");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"creation_date", value:"2011-11-10 16:16:16 +0530 (Thu, 10 Nov 2011)");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_name("AbsoluteFTP 'LIST' Command Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71210");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18102");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/106797/absoluteftp-overflow.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary code within the context of the application. Failed attacks may cause
a denial of service condition.");
  script_tag(name:"affected", value:"AbsoluteFTP versions 1.9.6 through 2.2.10");
  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing an overly
long 'LIST' command. This can be exploited to cause a stack-based buffer
overflow via a specially crafted FTP LIST command.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"AbsoluteFTP is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\VanDyke\AbsoluteFTP\Install";
if(!registry_key_exists(key:key)) {
  exit(0);
}

path = registry_get_sz(key:key, item:"Main Directory");
if(!path){
  exit(0);
}

version = fetch_file_version(sysPath:path, file_name:"AbsoluteFTP.exe");
if(version)
{
  if(version_in_range(version:version, test_version:"1.9.6", test_version2:"2.2.10.252")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

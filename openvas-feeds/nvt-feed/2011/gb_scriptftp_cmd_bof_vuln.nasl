# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902571");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-2011-3976");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("ScriptFTP 'GETLIST' or 'GETFILE' Commands Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46099/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49707");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17876/");
  script_xref(name:"URL", value:"http://www.digital-echidna.org/2011/09/scriptftp-3-3-remote-buffer-overflow-exploit-0day/");

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
  script_tag(name:"affected", value:"ScriptFTP version 3.3 and prior.");
  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing filenames
within a directory listing. This can be exploited to cause a stack-based buffer
overflow via a specially crafted FTP LIST command response.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"ScriptFTP is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\ScriptFTP";
if(!registry_key_exists(key:key)) {
  exit(0);
}

path = registry_get_sz(key:key, item:"Install_Dir");
if(!path){
  exit(0);
}

version = fetch_file_version(sysPath:path, file_name:"ScriptFTP.exe");
if(version)
{
  if(version_is_less_equal(version:version, test_version:"3.3")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

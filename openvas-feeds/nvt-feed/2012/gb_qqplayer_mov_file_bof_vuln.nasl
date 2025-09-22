# SPDX-FileCopyrightText: 2012  Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802367");
  script_version("2023-10-13T05:06:09+0000");
  script_cve_id("CVE-2011-5006");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:09 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-01-02 12:43:57 +0530 (Mon, 02 Jan 2012)");
  script_name("QQPlayer MOV File Processing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://1337day.com/exploits/16899");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50739");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46924");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71368");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18137/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execution of
arbitrary code.");
  script_tag(name:"affected", value:"QQPlayer version 3.2.845 and prior.");
  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing MOV files,
Which can be exploited to cause a stack based buffer overflow by sending
specially crafted MOV file with a malicious PnSize value.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"QQPlayer is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

qqplName = "SOFTWARE\Tencent\QQPlayer";
if(!registry_key_exists(key:qqplName)){
  exit(0);
}

qqplVer = registry_get_sz(key:qqplName, item:"Version");
if(qqplVer != NULL)
{
  if(version_is_less_equal(version:qqplVer, test_version:"3.2.845.400")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);

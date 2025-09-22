# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901106");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2010-1465");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Trellian FTP 'PASV' Response Buffer Overflow Vulnerability");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("FTP");
  script_dependencies("secpod_trellian_ftp_detect.nasl");
  script_mandatory_keys("TrellianFTP/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary code within the context of the affected application.");
  script_tag(name:"affected", value:"Trellian FTP version 3.1.3.1789 and prior.");
  script_tag(name:"insight", value:"The flaw is due to improper bounds checking when processing
long FTP 'PASV' responses.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Trellian FTP is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39370");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39598");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57778");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12152");
  exit(0);
}


include("version_func.inc");

trellianVer = get_kb_item("TrellianFTP/Version");

if(trellianVer)
{
  if(version_is_less_equal(version:trellianVer, test_version:"3.1.3.1789")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

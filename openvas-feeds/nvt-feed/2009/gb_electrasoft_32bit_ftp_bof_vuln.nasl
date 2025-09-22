# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800569");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1592", "CVE-2009-1611", "CVE-2009-1675");
  script_name("ElectraSoft 32bit FTP Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34993");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34822");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34838");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8614");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8613");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8623");
  script_xref(name:"URL", value:"http://www.electrasoft.com/readmef.txt");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50337");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_electrasoft_32bit_ftp_detect.nasl");
  script_mandatory_keys("ElectraSoft/FTP/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  codes within the context of the application by connecting to malicious
  FTP servers or can cause the application to crash.");
  script_tag(name:"affected", value:"ElectraSoft 32bit FTP 09.04.24 and prior on Windows");
  script_tag(name:"insight", value:"A boundary error occurs while processing,

  - response received from an FTP server with overly long banners.

  - an overly long 257 reply to a CWD command.

  - an overly long 227 reply to a PASV command.");
  script_tag(name:"solution", value:"Upgrade to 32bit FTP version 09.05.01.");
  script_tag(name:"summary", value:"ElectraSoft 32bit FTP client is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

bitftpVer = get_kb_item("ElectraSoft/FTP/Ver");
if(!bitftpVer)
  exit(0);

if(version_is_less_equal(version:bitftpVer, test_version:"09.04.24")){
  report = report_fixed_ver(installed_version:bitftpVer, vulnerable_range:"Less than or equal to 09.04.24");
  security_message(port: 0, data: report);
}

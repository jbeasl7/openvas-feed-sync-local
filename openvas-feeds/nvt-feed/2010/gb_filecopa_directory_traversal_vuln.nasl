# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800179");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2112");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_name("FileCopa FTP Server Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39843");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_filecopa_ftp_server_detect.nasl");
  script_mandatory_keys("FileCOPA-FTP-Server/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to read or overwrite arbitrary
  files via unknown vectors.");

  script_tag(name:"affected", value:"FileCopa FTP Server version before 5.03 on Windows.");

  script_tag(name:"insight", value:"An input validation error exists within the FTP service, which can be
  exploited to download or upload arbitrary files outside the FTP root
  via directory traversal attack.");

  script_tag(name:"solution", value:"Upgrade to FileCopa FTP Server version 5.03 or later.");

  script_tag(name:"summary", value:"FileCopa FTP Server is prone to a directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

filecopaVer = get_kb_item("FileCOPA-FTP-Server/Ver");
if(!filecopaVer){
  exit(0);
}

if(version_is_less(version:filecopaVer, test_version:"5.03")){
  report = report_fixed_ver(installed_version:filecopaVer, fixed_version:"5.03");
  security_message(port: 0, data: report);
}

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800226");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0349");
  script_name("FTPShell Server Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33597");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33403");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7852");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_ftpshell_server_detect.nasl");
  script_mandatory_keys("FTPShell/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a malicious license
  registry key file and can cause arbitrary code execution by tricking user
  to install the crafted malicious license registry file and may cause denial-of-service to the application.");

  script_tag(name:"affected", value:"FTPShell Server version 4.3.0 or prior on Windows.");

  script_tag(name:"insight", value:"This flaw is due to a boundary error in the FTPShell server application
  when processing certain Windows registry keys.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"FTPshell Server is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ftpShellVer = get_kb_item("FTPShell/Version");
if(!ftpShellVer){
  exit(0);
}

if(version_is_less_equal(version:ftpShellVer, test_version:"4.3.0")){
  security_message(port:0);
}

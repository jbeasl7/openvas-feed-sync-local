# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900511");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6186");
  script_name("RaidenFTPD Server CWD and MLST Command Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32216");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31741");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6742");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_raidenftpd_server_detect.nasl");
  script_mandatory_keys("RaidenFTPD/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the user crash the application to cause
  denial of service.");

  script_tag(name:"affected", value:"RaidenFTPD Server version 2.4.3620 and prior.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when handling overly long requested
  directory names. As a result buffer overflow can be caused using specially crafted CWD and MLST commands.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"summary", value:"RaidenFTPD Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

rftpdVer = get_kb_item("RaidenFTPD/Ver");
if(!rftpdVer){
  exit(0);
}

if(version_is_less_equal(version:rftpdVer, test_version:"2.4.3620")){
  report = report_fixed_ver(installed_version:rftpdVer, vulnerable_range:"Less than or equal to 2.4.3620");
  security_message(port: 0, data: report);
}

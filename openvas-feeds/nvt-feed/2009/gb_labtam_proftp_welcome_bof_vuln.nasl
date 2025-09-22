# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900980");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3976");
  script_name("Labtam ProFTP Welcome Message Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36446/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36128");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9508");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2414");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_labtam_proftp_detect.nasl");
  script_mandatory_keys("Labtam/ProFTP/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue by executing arbitrary code by tricking a
  user into connecting to a malicious FTP server and to crash an application.");
  script_tag(name:"affected", value:"Labtam ProFTP version 2.9 and prior on Windows.");
  script_tag(name:"insight", value:"A boundary error occurs when processing overly long welcome message sent by
  a FTP server.");
  script_tag(name:"solution", value:"Upgrade to ProFTP Version 3.0 or later.");
  script_tag(name:"summary", value:"Labtam ProFTP is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.labtam-inc.com/index.php");
  exit(0);
}

include("version_func.inc");

pfVer = get_kb_item("Labtam/ProFTP/Ver");
if(!pfVer){
  exit(0);
}

if(version_is_less_equal(version:pfVer, test_version:"2.9")){
  report = report_fixed_ver(installed_version:pfVer, vulnerable_range:"Less than or equal to 2.9");
  security_message(port: 0, data: report);
}

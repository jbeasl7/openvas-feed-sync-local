# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801318");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-1349");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser 'Content-Length' Header Buffer Overflow Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38519");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11622");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0529");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023690.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an affected browser
  or execute arbitrary code.");

  script_tag(name:"affected", value:"Opera version 10.10 on Linux.");

  script_tag(name:"insight", value:"The flaw is due to a buffer overflow error when processing malformed
  HTTP 'Content-Length:' headers.");

  script_tag(name:"solution", value:"Upgrade to Opera version 10.53 or later.");

  script_tag(name:"summary", value:"Opera Web Browser is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less_equal(version:operaVer, test_version:"10.10")){
  report = report_fixed_ver(installed_version:operaVer, vulnerable_range:"Less or equal to 10.10");
  security_message(port: 0, data: report);
}

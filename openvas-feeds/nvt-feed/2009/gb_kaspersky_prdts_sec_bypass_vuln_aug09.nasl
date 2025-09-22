# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800850");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-06 06:50:55 +0200 (Thu, 06 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2647");
  script_name("Kaspersky AntiVirus and Internet Security Unspecified Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35978");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35789");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51986");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1998");
  script_xref(name:"URL", value:"http://www.kaspersky.com/technews?id=203038755");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/products/installed");

  script_tag(name:"impact", value:"Successful attacks lets the attacker to bypass security restrictions.");

  script_tag(name:"affected", value:"Kaspersky Anti-Virus/Internet Security 2010 version prior to 9.0.0.463.");

  script_tag(name:"insight", value:"Issue is caused by an unspecified error which could allow an external script
  to disable the computer protection, facilitating further attacks.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Critical Fix 1 (version 9.0.0.463).");

  script_tag(name:"summary", value:"Kaspersky AntiVirus or Internet Security is prone to an unspecified vulnerability.");
  exit(0);
}

include("version_func.inc");

# For Kaspersky AntiVirus
kavVer = get_kb_item("Kaspersky/AV/Ver");
if(kavVer != NULL) {
  if(version_in_range(version:kavVer, test_version:"9.0", test_version2:"9.0.0.462")) {
    report = report_fixed_ver(installed_version:kavVer, vulnerable_range:"9.0 - 9.0.0.462");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# For Kaspersky Internet Security
kisVer = get_kb_item("Kaspersky/IntNetSec/Ver");
if(kisVer != NULL) {
  if(version_in_range(version:kisVer, test_version:"9.0", test_version2:"9.0.0.462")) {
    report = report_fixed_ver(installed_version:kisVer, vulnerable_range:"9.0 - 9.0.0.462");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

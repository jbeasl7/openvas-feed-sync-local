# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802362");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2011-4681", "CVE-2011-4682", "CVE-2011-4683", "CVE-2011-4684",
                "CVE-2011-4685", "CVE-2011-4686", "CVE-2011-4687");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-12-09 15:35:28 +0530 (Fri, 09 Dec 2011)");
  script_name("Opera Multiple Vulnerabilities (Dec 2011) - Mac OS X");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1003/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1005/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/mac/1160/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_mandatory_keys("Opera/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial-of-service condition.");
  script_tag(name:"affected", value:"Opera version before 11.60.");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Improper handling of the number of .(dot) characters that conventionally
    exist in domain names of different top-level domains.

  - Implementation errors in the 'JavaScript' engine, 'Web Workers' and 'in'
    operator.

  - An error when handling certificate revocation related to 'corner cases'.

  - An error in Dragonfly in opera.");
  script_tag(name:"solution", value:"Upgrade to the Opera version 11.60 or later.");
  script_tag(name:"summary", value:"Opera is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.60")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.60");
  security_message(port: 0, data: report);
}

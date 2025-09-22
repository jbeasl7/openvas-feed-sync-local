# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802755");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2011-2628", "CVE-2011-2629", "CVE-2011-2630", "CVE-2011-2631",
                "CVE-2011-2632", "CVE-2011-2633");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-04-19 11:17:38 +0530 (Thu, 19 Apr 2012)");
  script_name("Opera Browser Multiple Vulnerabilities-01 (Jul 2011) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44611");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48570");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/992/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/mac/1111/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_mandatory_keys("Opera/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code and cause a denial of service.");
  script_tag(name:"affected", value:"Opera Web Browser Version prior 11.11 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to an error,

  - In certain frameset constructs, fails to correctly handle when the page
    is unloaded, causing a memory corruption.

  - When reloading page after opening a pop-up of easy-sticky-note extension.

  - In Cascading Style Sheets (CSS) implementation, when handling the
    column-count property.

  - When handling destruction of a silver light instance.");
  script_tag(name:"solution", value:"Upgrade to Opera Web Browser Version 11.11 or later.");
  script_tag(name:"summary", value:"Opera browser is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.11")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.11");
  security_message(port:0, data:report);
}

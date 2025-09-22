# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803003");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-4142", "CVE-2012-4143", "CVE-2012-4144", "CVE-2012-4145");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-08-08 10:50:33 +0530 (Wed, 08 Aug 2012)");
  script_name("Opera Multiple Vulnerabilities (Aug 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54780");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54782");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54788");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1025/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1026/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1027/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/mac/1166/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/mac/1201/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_mandatory_keys("Opera/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  script code, disclose sensitive information, or spoof the originating URL
  of a trusted web site and carry out phishing-style attacks.");
  script_tag(name:"affected", value:"Opera version prior to 11.66 and 12.x before 12.01 on Mac OS X");
  script_tag(name:"insight", value:"- Multiple unspecified errors.

  - An error when certain characters in HTML documents are ignored under some
    circumstances, which allows to conduct XSS attacks.

  - The improper implementation of download dialog feature, which allows
    attackers to trick users into downloading and executing arbitrary files
    via a small window for the download dialog.

  - Fails to escape characters in DOM elements, which allows to conduct
    XSS attacks.");
  script_tag(name:"solution", value:"Upgrade to Opera version 11.66 or 12.01 or later.");
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

if(version_is_less(version:operaVer, test_version:"11.66")||
   version_is_equal(version: operaVer, test_version:"12.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

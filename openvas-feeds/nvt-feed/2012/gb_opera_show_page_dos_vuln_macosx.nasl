# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803004");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-4146");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-08-08 12:50:33 +0530 (Wed, 08 Aug 2012)");
  script_name("Opera Multiple Vulnerabilities (Aug 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/mac/1201/");
  script_xref(name:"URL", value:"http://www.scaprepo.com/view.jsp?id=CVE-2012-4146");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_mandatory_keys("Opera/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the browser leading to
  denial of service condition.");
  script_tag(name:"affected", value:"Opera version prior to 12.01 on Mac OS X");
  script_tag(name:"insight", value:"An error caused via a crafted web site on Lenovos 'Shop now' page.");
  script_tag(name:"solution", value:"Upgrade to Opera version 12.01 or later.");
  script_tag(name:"summary", value:"Opera is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"12.01")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"12.01");
  security_message(port:0, data:report);
}

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801371");
  script_version("2024-02-28T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2659");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Opera Browser < 10.50 'widget' Information Disclosure Vulnerability (Jul 2010) - Windows");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/959/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/mac/1052/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1673");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/1050/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will let attackers obtain potentially sensitive
  information via a crafted web site.");
  script_tag(name:"affected", value:"Opera version prior to 10.50 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to error in handling of 'widget' properties, which
  makes widget properties accessible to third-party domains.");
  script_tag(name:"solution", value:"Upgrade to Opera 10.50 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Opera web browser is prone to an information disclosure vulnerability.");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"10.50")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"10.50");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

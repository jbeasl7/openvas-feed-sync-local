# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801331");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1728");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser 'document.write()' Code execution Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39590");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58231");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/953/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0999");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/1053/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to corrupt memory and execute
  arbitrary code by tricking a user into visiting a specially crafted web page.");
  script_tag(name:"affected", value:"Opera version prior to 10.53 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an error when continuously modifying document content
  on a web page using 'document.write()' function.");
  script_tag(name:"solution", value:"Upgrade to the opera version 10.53 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Opera web browser is prone to an arbitrary code execution vulnerability.");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"10.53")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"10.53");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

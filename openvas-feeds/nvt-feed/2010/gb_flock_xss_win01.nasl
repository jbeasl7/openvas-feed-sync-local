# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902314");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3262");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Flock Browser RSS Feed Cross site scripting Vulnerability");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_flock_detect_win.nasl");
  script_mandatory_keys("Flock/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute HTML code in the
  context of the affected browser, bypass the same-origin protection and obtain
  potentially sensitive information.");
  script_tag(name:"affected", value:"Flock versions 3.0 to 3.0.0.4113");
  script_tag(name:"insight", value:"The flaw is due to the improper validation of user-supplied input
  when processing RSS feeds.");
  script_tag(name:"solution", value:"Upgrade to the Flock version 3.0.0.4114");
  script_tag(name:"summary", value:"Flock browser is prone to a cross-site scripting (XSS) vulnerability.");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513701/100/0/threaded");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.flock.com/");
  exit(0);
}


include("version_func.inc");

flockVer = get_kb_item("Flock/Win/Ver");
if(!flockVer){
  exit(0);
}

if(version_in_range(version:flockVer, test_version:"3.0", test_version2:"3.0.0.4113")){
  report = report_fixed_ver(installed_version:flockVer, vulnerable_range:"3.0 - 3.0.0.4113");
  security_message(port: 0, data: report);
}

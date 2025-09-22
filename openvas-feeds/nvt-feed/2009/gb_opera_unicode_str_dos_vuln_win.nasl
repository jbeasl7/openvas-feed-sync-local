# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900803");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2577", "CVE-2008-7245", "CVE-2009-3269");
  script_name("Opera Unicode String Denial Of Service Vulnerability - Windows");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3338/");
  script_xref(name:"URL", value:"http://websecurity.com.ua/2456/");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3194/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/505092/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506328/100/100/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation lets the attacker cause memory or CPU consumption,
  resulting in Denial of Service condition.");
  script_tag(name:"affected", value:"Opera version 9.52 and prior on Windows.");
  script_tag(name:"insight", value:"- Error caused by calling the 'window.print' function in a loop aka a
    'printing DoS attack'.

  - CPU consumption issue exists when a series of automatic submissions
    of a form containing a KEYGEN element.

  - Error exists when application fails to handle user supplied input into
    the 'write' method via a long Unicode string argument.");
  script_tag(name:"solution", value:"Upgrade to Opera Version 10 or later.");
  script_tag(name:"summary", value:"Opera is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less_equal(version:operaVer, test_version:"9.52")){
  report = report_fixed_ver(installed_version:operaVer, vulnerable_range:"Less than or equal to 9.52");
  security_message(port: 0, data: report);
}

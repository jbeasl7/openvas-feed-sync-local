# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801875");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1712");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Mozilla Firefox Information Disclosure Vulnerability - Windows");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.com/2011/03/multi-browser-heap-address-leak-in-xslt.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain potentially
  sensitive information about heap memory addresses.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.6.16 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error in txXPathNodeUtils::getXSLTId function
  in txStandaloneXPathTreeWalker.cpp allows remote attackers to obtain
  potentially sensitive information about heap memory addresses via an XML
  document containing a call to the XSLT generate-id XPath function.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 4 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(!vers)
  exit(0);

if(version_is_less_equal(version:vers, test_version:"3.6.16")){
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 3.6.16");
  security_message(port: 0, data: report);
}

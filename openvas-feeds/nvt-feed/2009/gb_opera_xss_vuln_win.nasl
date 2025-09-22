# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800651");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-2351");
  script_name("Opera Web Browser 'Refresh' Header XSS Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504718/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35571");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful remote attack could execute arbitrary script code in the context
  of the user running the application and to steal cookie-based authentication
  credentials and other sensitive data that may aid in further attacks.");
  script_tag(name:"affected", value:"Opera version 9.52 and prior on Windows.");
  script_tag(name:"insight", value:"Flaw is due to error in Refresh headers in HTTP responses. It does not block
  javascript: URIs, while injecting a Refresh header or specifying the content
  of a Refresh header");
  script_tag(name:"solution", value:"Upgrade to Opera version 9.64 or later.");
  script_tag(name:"summary", value:"Opera Web Browser is prone to a cross-site scripting (XSS) vulnerability.");
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

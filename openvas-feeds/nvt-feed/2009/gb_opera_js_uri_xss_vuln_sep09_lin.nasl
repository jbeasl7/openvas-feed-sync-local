# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800882");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3013");
  script_name("Opera 'javascript: URI' XSS Vulnerability (Sep 2009) - Linux");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3386/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Build/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct Cross-Site Scripting
  attacks in the victim's system.");
  script_tag(name:"affected", value:"Opera version 9.52 and prior and 10.00 Beta 3 Build 1699 on Linux.");
  script_tag(name:"insight", value:"Error occurs when application fails to sanitise the 'javascript:' and 'data:'
  URIs in Location headers in HTTP responses, which can be exploited via vectors
  related to injecting a Location header.");
  script_tag(name:"solution", value:"Upgrade to Opera version 9.64 or later and 10.10 or later.");
  script_tag(name:"summary", value:"Opera Web Browser is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.opera.com/");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Build/Linux/Ver");
if(isnull(operaVer))
{
  exit(0);
}

#                    and 10.00 Beta 3 Build 1699 (10.00.1699)
if(version_is_less_equal(version:operaVer, test_version:"9.52.2091")||
   version_is_equal(version:operaVer, test_version:"10.00.1699")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

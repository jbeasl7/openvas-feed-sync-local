# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800897");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3018");
  script_name("Maxthon 'javascript:' And 'data:' URI XSS Vulnerability");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3386/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506163/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_maxthon_detect.nasl");
  script_mandatory_keys("Maxthon/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct
Cross-Site Scripting attacks in the victim's system.");
  script_tag(name:"affected", value:"Maxthon version 3.0.0.145 on Windows.");
  script_tag(name:"insight", value:"Error occurs when application fails to sanitise the
'javascript:' and 'data:' URIs in Refresh headers or Location headers in HTTP
responses, which can be exploited via vectors related to injecting a Refresh
header or Location HTTP response header.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Maxthon Browser is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

maxthonVer = get_kb_item("Maxthon/Ver");

if(maxthonVer)
{
  if(version_is_equal(version:maxthonVer, test_version:"3.0.0.145")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

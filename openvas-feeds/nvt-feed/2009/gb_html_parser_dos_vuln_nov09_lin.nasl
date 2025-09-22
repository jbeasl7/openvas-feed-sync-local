# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801039");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3627");
  script_name("HTML-Parser 'decode_entities()' Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37155");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36807");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53941");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/10/23/9");
  script_xref(name:"URL", value:"https://issues.apache.org/SpamAssassin/show_bug.cgi?id=6225");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_html_parser_detect_lin.nasl");
  script_mandatory_keys("HTML-Parser/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service condition.");
  script_tag(name:"affected", value:"HTML-Parser versions prior to 3.63 on Linux.");
  script_tag(name:"insight", value:"The flaw is due to an error within the 'decode_entities()' function in 'utils.c',
  which can be exploited to cause an infinite loop by tricking an application into
  processing a specially crafted string using this library.");
  script_tag(name:"summary", value:"HTML-Parser is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"solution", value:"Upgrade to HTML-Parser version 3.63 or later.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

parserVer = get_kb_item("HTML-Parser/Linux/Ver");
if(!parserVer)
  exit(0);

if(version_is_less(version:parserVer, test_version:"3.63")){
  report = report_fixed_ver(installed_version:parserVer, fixed_version:"3.63");
  security_message(port: 0, data: report);
}

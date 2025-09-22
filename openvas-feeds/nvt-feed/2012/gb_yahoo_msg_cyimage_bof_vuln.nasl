# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802419");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-0268");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-01-23 14:36:01 +0530 (Mon, 23 Jan 2012)");
  script_name("Yahoo Messenger JPG Photo Sharing Integer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47041");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51405");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_yahoo_msg_detect.nasl");
  script_mandatory_keys("YahooMessenger/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to a heap-based buffer
  overflow via a specially crafted JPG file.");
  script_tag(name:"affected", value:"Yahoo! Messenger version prior to 11.5.0.155 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an integer overflow error in the
  'CYImage::LoadJPG()' method (YImage.dll) when allocating memory using the
  image dimension values.");
  script_tag(name:"solution", value:"Upgrade to Yahoo! Messenger version 11.5.0.155 or later.");
  script_tag(name:"summary", value:"Yahoo! Messenger is prone to an integer overflow vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://messenger.yahoo.com/download/");
  exit(0);
}


include("version_func.inc");

ymsgVer = get_kb_item("YahooMessenger/Ver");
if(!ymsgVer){
  exit(0);
}

if(version_is_less(version:ymsgVer, test_version:"11.5.0.0155")){
  report = report_fixed_ver(installed_version:ymsgVer, fixed_version:"11.5.0.0155");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

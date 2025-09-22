# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800551");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1234");
  script_name("Opera Web Browser XML Denial Of Service Vulnerability - Linux");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34298");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49522");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a malicious XML page
  and cause denial of service by persuading the user to open the malicious
  arbitrary page.");
  script_tag(name:"affected", value:"Opera version 9.64 and prior on Linux.");
  script_tag(name:"insight", value:"This flaw is due to improper boundary check while parsing XML
  documents containing an overly large number of nested elements.");
  script_tag(name:"solution", value:"Upgrade to Opera version 10.00 or later.");
  script_tag(name:"summary", value:"Opera Web Browser is prone to XML Denial of Service vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less_equal(version:operaVer, test_version:"9.64")){
  report = report_fixed_ver(installed_version:operaVer, vulnerable_range:"Less than or equal to 9.64");
  security_message(port: 0, data: report);
}

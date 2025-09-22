# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800519");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0569");
  script_name("Becky! Internet Mail Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33892");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33756");
  script_xref(name:"URL", value:"http://www.rimarts.jp/downloads/B2/Readme-e.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_becky_internet_mail_detect.nasl");
  script_mandatory_keys("Becky/InternetMail/Ver");
  script_tag(name:"affected", value:"Becky! Internet Mail version 2.48.2 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is generated when the application fails to perform adequate boundary
  checks on user-supplied input. Boundary error may be generated when the user
  agrees to return a receipt message for a specially crafted e-mail thus
  leading to buffer overflow.");
  script_tag(name:"solution", value:"Update to version 2.50.01 or later.");
  script_tag(name:"summary", value:"Becky! Internet Mail client is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to execute arbitrary
  code on the target system and can cause denial-of-service condition.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

bimVer = get_kb_item("Becky/InternetMail/Ver");
if(!bimVer)
  exit(0);

if(version_is_less_equal(version:bimVer, test_version:"2.4.8.2")){
  report = report_fixed_ver(installed_version:bimVer, vulnerable_range:"Less than or equal to 2.4.8.2");
  security_message(port: 0, data: report);
}

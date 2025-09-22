# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801313");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-1239");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Foxit Reader Arbitrary Command Execution Vulnerability");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/570177");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/pdf/reader/security.htm#0401");
  script_xref(name:"URL", value:"http://blog.didierstevens.com/2010/03/29/escape-from-pdf/");
  script_xref(name:"URL", value:"http://blog.didierstevens.com/2010/03/31/escape-from-foxit-reader/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  script_tag(name:"impact", value:"Successful exploitation will let attacker to execute arbitrary code or crash an
  affected application.");
  script_tag(name:"affected", value:"Foxit Reader version prior to 3.2.1.0401");
  script_tag(name:"insight", value:"The flaw exists due to error in handling 'PDF' files which runs executable
  embedded program inside a PDF automatically without asking for user permission.");
  script_tag(name:"solution", value:"Upgrade to the version 3.2.1.0401 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Foxit Reader is prone to an arbitrary command execution vulnerability.");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/downloads/");
  exit(0);
}


include("version_func.inc");

foxVer = get_kb_item("foxit/reader/ver");
if(foxVer)
{
  if(version_is_less(version:foxVer,test_version:"3.2.1.0401")){
    report = report_fixed_ver(installed_version:foxVer, fixed_version:"3.2.1.0401");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

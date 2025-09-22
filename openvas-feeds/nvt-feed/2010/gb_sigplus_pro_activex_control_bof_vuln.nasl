# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801252");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_cve_id("CVE-2010-2931");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("SigPlus Pro ActiveX Control 'LCDWriteString()' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42109");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60839");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14514");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_sigplus_pro_activex_detect.nasl");
  script_mandatory_keys("SigPlus/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code on the system or cause the victim's browser to crash.");

  script_tag(name:"affected", value:"SigPlus Pro ActiveX control version 3.74.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in SigPlus.ocx when handling the
  'HexString' argument passed to the 'LCDWriteString()' method and can be
  exploited to cause a stack-based buffer overflow via an overly long string.");

  script_tag(name:"solution", value:"Upgrade to SigPlus Pro ActiveX control version 3.95 or later.");

  script_tag(name:"summary", value:"SigPlus Pro ActiveX Control is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

sigVer = get_kb_item("SigPlus/Ver");

if(sigVer)
{
  if(version_is_less_equal(version:sigVer, test_version:"3.74") ){
    report = report_fixed_ver(installed_version:sigVer, vulnerable_range:"Less or equal to 3.74");
    security_message(port: 0, data: report);
  }
}

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801425");
  script_cve_id("CVE-2010-1797");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Foxit Reader Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42241");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/pdf/reader/security_bulletins.php#iphone");
  script_xref(name:"URL", value:"http://www.us-cert.gov/current/index.html#foxit_releases_foxit_reader_4");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  in the context of an application that uses the affected library. Failed
  exploit attempts will likely result in denial-of-service conditions.");
  script_tag(name:"affected", value:"Foxit Reader version prior to 4.1.1 (4.1.1.0805)");
  script_tag(name:"insight", value:"Multiple flaws are due to an error in the handling of 'PDF'
  documents. It is not properly rendering the PDF documents.");
  script_tag(name:"solution", value:"Upgrade to the Foxit Reader version 4.1.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Foxit Reader is prone to multiple buffer overflow vulnerabilities.");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/downloads/index.php");
  exit(0);
}


include("version_func.inc");

foxitVer = get_kb_item("foxit/reader/ver");
if(!foxitVer){
  exit(0);
}

if(version_is_less(version:foxitVer, test_version:"4.1.1.0805")){
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"4.1.1.0805");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

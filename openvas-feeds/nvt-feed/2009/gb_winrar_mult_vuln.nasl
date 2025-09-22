# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901022");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7144");
  script_name("WinRAR Multiple Unspecified Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29407");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/41251");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/0916/references");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_winrar_detect.nasl");
  script_mandatory_keys("WinRAR/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause heap corruptions
  or stack-based buffer overflows or execution of arbitrary code.");
  script_tag(name:"affected", value:"WinRAR versions prior to 3.71");
  script_tag(name:"insight", value:"The flaw is due to unspecified errors in the processing of several
  archive files.");
  script_tag(name:"solution", value:"Upgrade to WinRAR version 3.71 or later.");
  script_tag(name:"summary", value:"WinRAR is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

winrarVer = get_kb_item("WinRAR/Ver");
if(winrarVer != NULL)
{
  if(version_is_less(version:winrarVer, test_version:"3.71")){
     report = report_fixed_ver(installed_version:winrarVer, fixed_version:"3.71");
     security_message(port: 0, data: report);
   }
}

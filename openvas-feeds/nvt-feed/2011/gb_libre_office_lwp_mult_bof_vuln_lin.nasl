# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902700");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_cve_id("CVE-2011-2685");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("LibreOffice LWP File Processing Multiple Buffer Overflow Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_libre_office_detect_lin.nasl");
  script_mandatory_keys("LibreOffice/Linux/Ver");
  script_tag(name:"insight", value:"The flaws are due to errors in the import filter when processing Lotus
  Word Pro (LWP) files and can be exploited to cause a stack-based buffer
  overflow via a specially crafted file.");
  script_tag(name:"solution", value:"Upgrade to LibreOffice version 3.3.3 or 3.4.0 or later.");
  script_tag(name:"summary", value:"LibreOffice is prone to multiple buffer overflow vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"LibreOffice version prior to 3.3.3");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44996/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/953183");
  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("LibreOffice/Linux/Ver");
if(!officeVer){
  exit(0);
}

if(version_is_less(version:officeVer, test_version:"3.3.301")){
  report = report_fixed_ver(installed_version:officeVer, fixed_version:"3.3.301");
  security_message(port: 0, data: report);
}

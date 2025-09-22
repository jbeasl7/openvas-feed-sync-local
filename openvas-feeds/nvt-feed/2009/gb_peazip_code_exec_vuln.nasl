# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800593");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2261");
  script_name("PeaZIP < 2.6.2 RCE Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.vulnaware.com/?p=16018");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35352/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_peazip_detect_win.nasl");
  script_mandatory_keys("PeaZIP/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code on
  the affected system via files containing shell metacharacters and commands
  contained in a ZIP archive.");
  script_tag(name:"affected", value:"PeaZIP version 2.6.1 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is due to insufficient sanitation of input data while
  processing the names of archived files.");
  script_tag(name:"solution", value:"Update to version 2.6.2 or later.");
  script_tag(name:"summary", value:"PeaZIP is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

version = get_kb_item("PeaZIP/Win/Ver");
if(!version)
  exit(0);

if(version_is_less_equal(version:version, test_version:"2.6.1")){
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Less than or equal to 2.6.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

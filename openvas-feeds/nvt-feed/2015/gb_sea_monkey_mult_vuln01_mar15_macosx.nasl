# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805513");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-0817", "CVE-2015-0818");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-03-27 14:54:29 +0530 (Fri, 27 Mar 2015)");
  script_name("SeaMonkey Multiple Vulnerabilities -01 (Mar 2015) - Mac OS X");

  script_tag(name:"summary", value:"SeaMonkey is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An out-of-bounds access error in asmjs/AsmJSValidate.cpp within the JavaScript
  Just-in-time Compilation (JIT).

  - An error in docshell/base/nsDocShell.cpp within the SVG format content navigation
  functionality.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges and conduct arbitrary code execution.");

  script_tag(name:"affected", value:"SeaMonkey version before 2.33.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to SeaMonkey version 2.33.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031958");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-29");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-28");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:smVer, test_version:"2.33.1"))
{
  report = 'Installed version: ' + smVer + '\n' +
             'Fixed version:     ' + "2.33.1"  + '\n';
  security_message(data:report);
  exit(0);
}

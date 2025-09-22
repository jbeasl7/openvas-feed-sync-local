# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:keynote";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802146");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_cve_id("CVE-2010-3785", "CVE-2010-3786", "CVE-2011-1417");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Apple Mac OS X iWork 9.1 Update");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_iwork_detect_macosx.nasl");
  script_mandatory_keys("apple/iwork/keynote/detected");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4684");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44799");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46832");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2011//Jul/msg00003.html");
  script_xref(name:"URL", value:"http://support.apple.com/downloads/DL1097/en_US/iWork9.1Update.dmg");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to opening a maliciously
  crafted files, which leads to an unexpected application termination or arbitrary code execution.");

  script_tag(name:"affected", value:"Mac OS X iWork version 9.0 through 9.0.5.");

  script_tag(name:"insight", value:"The flaws are due to

  - a buffer overflow error, while handling the 'Excel' files.

  - a memory corruption issue, while handling the 'Excel' files and Microsoft
  Word documents.");

  script_tag(name:"solution", value:"Apply the update from the referenced link.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X iWork 9.1 Update.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

## Refer below wiki link for version mapping
## http://en.wikipedia.org/wiki/IWork
## After installing the update, keynote version will gets update
if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.1.1 (Note: this is the version of Keynote shipped with the fixed iWork 9.1)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

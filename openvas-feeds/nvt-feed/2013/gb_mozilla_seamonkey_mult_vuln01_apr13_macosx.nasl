# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803472");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0791", "CVE-2013-0792",
                "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0797",
                "CVE-2013-0800");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-04-08 15:42:50 +0530 (Mon, 08 Apr 2013)");
  script_name("Mozilla SeaMonkey Multiple Vulnerabilities -01 (Apr 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58819");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58821");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58828");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58835");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58836");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58837");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52293");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=825721");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption, bypass certain security restrictions and compromise
  a user's system.");
  script_tag(name:"affected", value:"Mozilla SeaMonkey version before 2.17 on Mac OS X");
  script_tag(name:"insight", value:"- Unspecified vulnerabilities in the browser engine

  - Buffer overflow in the Mozilla Maintenance Service

  - Not preventing origin spoofing of tab-modal dialogs

  - Untrusted search path vulnerability while handling dll files

  - Improper validation of address bar during history navigation

  - Integer signedness error in the 'pixman_fill_sse2' function in
    'pixman-sse2.c' in Pixman

  - Error in 'CERT_DecodeCertPackage' function in Mozilla Network Security
    Services (NSS)

  - Improper handling of color profiles during PNG rendering in
    'gfx.color_management.enablev4'

  - The System Only Wrapper (SOW) implementation does not prevent use of the
    cloneNode method for cloning a protected node");
  script_tag(name:"solution", value:"Upgrade to Mozilla SeaMonkey version 2.17 or later.");
  script_tag(name:"summary", value:"Mozilla SeaMonkey is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.17"))
  {
    report = report_fixed_ver(installed_version:smVer, fixed_version:"2.17");
    security_message(port: 0, data: report);
    exit(0);
  }
}

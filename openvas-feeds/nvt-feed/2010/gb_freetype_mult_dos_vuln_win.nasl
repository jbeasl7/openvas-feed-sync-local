# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901142");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3053", "CVE-2010-2808", "CVE-2010-2807",
                "CVE-2010-2806", "CVE-2010-2805", "CVE-2010-2541");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeType <= 2.4.1 Multiple DoS Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40816");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42285");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2018");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/freetype/files/freetype2/2.4.2/NEWS/view");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_freetype_detect_win.nasl");
  script_mandatory_keys("FreeType/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation may allow attackers to execute arbitrary code in the
  context of an application that uses the affected library. Failed exploitation
  attempts will likely result in denial-of-service conditions.");
  script_tag(name:"affected", value:"FreeType version 2.4.1 and prior.");
  script_tag(name:"insight", value:"- Buffer overflow error in the 'Mac_Read_POST_Resource()' [src/base/ftobjs.c]
    function when processing Adobe Type 1 Mac Font File (LWFN) fonts.

  - Errors related to the bdf/bdflib.c, t42_parse_sfnts function in
    type42/t42parse.c, FT_Stream_EnterFrame function in base/ftstream.c,
    ftmulti.c in the ftmulti demo program and to the 'BOUNDS' macro when
    processing fonts.");
  script_tag(name:"solution", value:"Upgrade to FreeType version 2.4.2 or later.");
  script_tag(name:"summary", value:"FreeType is prone to multiple Denial of Service (DoS) vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ftVer = get_kb_item("FreeType/Win/Ver");
if(! ftVer) {
  exit(0);
}

if(ftVer != NULL)
{
  if(version_is_less(version: ftVer, test_version: "2.4.2")){
    report = report_fixed_ver(installed_version:ftVer, fixed_version:"2.4.2");
    security_message(port: 0, data: report);
  }
}

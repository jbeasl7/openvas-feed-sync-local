# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901143");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-2497", "CVE-2010-2498", "CVE-2010-2499",
                "CVE-2010-2500", "CVE-2010-2519", "CVE-2010-2520",
                "CVE-2010-2527");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeType Memory Corruption and Buffer Overflow Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1811");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/freetype/files/freetype2/2.4.0/NEWS/view");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_freetype_detect_win.nasl");
  script_mandatory_keys("FreeType/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation may allow attackers to execute arbitrary code in the
  context of an application that uses the affected library. Failed exploitation
  attempts will likely result in denial-of-service conditions.");
  script_tag(name:"affected", value:"FreeType versions prior to 2.4.0");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in the 'demo' programs.

  - A heap-based buffer overflow in the 'Ins_IUP function()' in
    'truetype/ttinterp.c' and 'Mac_Read_POST_Resource()' function in
    ' base/ftobjs.c'.

  - An integer overflow in the 'gray_render_span()' function in 'smooth/ftgrays.c'
    and integer underflow in 'glyph' handling.

  - A Buffer overflow in the 'Mac_Read_POST_Resource()' function in
    'base/ftobjs.c'.

  - An error in the 'psh_glyph_find_strong_pointr()' function in
   'pshinter/pshalgo.c'.
  when processing malformed font files.");
  script_tag(name:"solution", value:"Upgrade to FreeType version 2.4.2 or later.");
  script_tag(name:"summary", value:"FreeType is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.freetype.org/");
  exit(0);
}


include("version_func.inc");

ftVer = get_kb_item("FreeType/Win/Ver");
if(! ftVer) {
  exit(0);
}

if(ftVer != NULL)
{
  if(version_is_less(version: ftVer, test_version: "2.4.0")){
    report = report_fixed_ver(installed_version:ftVer, fixed_version:"2.4.0");
    security_message(port: 0, data: report);
  }
}

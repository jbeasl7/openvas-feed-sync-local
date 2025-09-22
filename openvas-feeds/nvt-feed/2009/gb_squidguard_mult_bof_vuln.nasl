# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800965");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3826", "CVE-2009-3700");
  script_name("SquidGuard Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37107");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36800");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53922");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3013");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Oct/1023079.html");
  script_xref(name:"URL", value:"http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091019");
  script_xref(name:"URL", value:"http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091015");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_squidguard_detect.nasl");
  script_mandatory_keys("SquidGuard/Ver");
  script_tag(name:"impact", value:"Remote attackers can exploit this issue to bypass the filter security and to
  cause Denial of Service due to application hang.");
  script_tag(name:"affected", value:"SquidGuard version 1.3 and 1.4");
  script_tag(name:"insight", value:"- A boundary error occurs in 'sgLog.c' while handling overly long URLs with
    multiple '/' characters while operating in the emergency mode.

  - Multiple buffer overflow errors occur in 'sg.h.in' and 'sgDiv.c.in' while
    processing overly long URLs and can be exploited to bypass the URL filter.");
  script_tag(name:"summary", value:"SquidGuard is prone to multiple Buffer Overflow vulnerabilities.");
  script_tag(name:"solution", value:"Apply the referenced patches.");
  exit(0);
}

include("version_func.inc");

sgVer = get_kb_item("SquidGuard/Ver");
if(!sgVer)
  exit(0);

if(version_is_equal(version:sgVer, test_version:"1.4")||
   version_is_equal(version:sgVer, test_version:"1.3")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

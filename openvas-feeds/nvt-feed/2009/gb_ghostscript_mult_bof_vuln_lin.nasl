# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:artifex:ghostscript";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900542");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0792", "CVE-2009-0196");
  script_name("Ghostscript < 8.71 Multiple Buffer Overflow Vulnerabilities - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_ghostscript_detect_lin.nasl");
  script_mandatory_keys("artifex/ghostscript/lin/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34292");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34445");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0983");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Apr/1022029.html");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to execute arbitrary code in
  the context of the affected application and to cause a denial of service.");

  script_tag(name:"affected", value:"Ghostscript version 8.64 and prior.");

  script_tag(name:"insight", value:"The flaws are due to:

  - A boundary error in the jbig2_symbol_dict.c() function in the JBIG2
  decoding library (jbig2dec) while decoding JBIG2 symbol dictionary segments.

  - multiple integer overflows in icc.c in the ICC Format library while
  processing malformed PDF and PostScript files with embedded images.");

  script_tag(name:"solution", value:"Upgrade to Ghostscript version 8.71 or later.");

  script_tag(name:"summary", value:"Ghostscript is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

location = infos["location"];
version = infos["version"];

if(version_is_less_equal(version:version, test_version:"8.64")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.71", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

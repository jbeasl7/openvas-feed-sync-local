# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900742");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0648", "CVE-2010-0654");
  script_name("Firefox Multiple Vulnerabilities (Feb 2010) - Windows");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=9877");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=32309");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to obtain sensitive information via
  a crafted document.");
  script_tag(name:"affected", value:"Firefox version prior to 3.6 on Windows.");
  script_tag(name:"insight", value:"- The malformed stylesheet document and cross-origin loading of CSS
    stylesheets even when the stylesheet download has an incorrect MIME type.

  - IFRAME element allows placing the site&qts URL in the HREF attribute of a
    stylesheet 'LINK' element, and then reading the 'document.styleSheets[0].href'
    property value.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.");
  script_tag(name:"summary", value:"Firefox Browser is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(isnull(ffVer)){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"3.6")){
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"3.6");
  security_message(port: 0, data: report);
}

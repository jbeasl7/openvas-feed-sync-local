# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801763");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)");
  script_cve_id("CVE-2011-1185", "CVE-2011-1187", "CVE-2011-1188", "CVE-2011-1189",
                "CVE-2011-1190", "CVE-2011-1191", "CVE-2011-1193", "CVE-2011-1194",
                "CVE-2011-1195", "CVE-2011-1196", "CVE-2011-1197", "CVE-2011-1198",
                "CVE-2011-1199", "CVE-2011-1200", "CVE-2011-1201", "CVE-2011-1202",
                "CVE-2011-1203", "CVE-2011-1204", "CVE-2011-1285", "CVE-2011-1286");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome Multiple Vulnerabilities (Mar 2011) - Windows");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/03/chrome-stable-release.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause denial-of-service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 10.0.648.127 on Windows");
  script_tag(name:"insight", value:"The flaws are due to

  - Not preventing 'navigation' and 'close' operations on the top location of a
    sandboxed frame.

  - Cross-origin error message leak.

  - Error in performing 'box layout'.

  - Memory corruption error in 'counter nodes'.

  - Error in 'Web Workers' implementation which allows remote attackers to
    bypass the Same Origin Policy via unspecified vectors, related to an error
    message leak.

  - Use-after-free vulnerability in 'DOM URL' handling.

  - Error in 'Google V8', which allows remote attackers to bypass the Same
    Origin Policy via unspecified vectors.

  - Use-after-free vulnerability in document script lifetime handling.

  - Error in performing 'table painting'.

  - Error in 'OGG' container implementation.

  - Use of corrupt out-of-bounds structure in video code.

  - Error in handling  DataView objects.

  - Bad cast in text rendering.

  - Error in context implementation in WebKit.

  - Unspecified vulnerability in the 'XSLT' implementation.

  - Not properly handling 'SVG' cursors.

  - 'DOM' tree corruption with attribute handling.

  - Corruption via re-entrancy of RegExp code.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 10.0.648.127 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"10.0.648.127")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"10.0.648.127");
  security_message(port: 0, data: report);
}

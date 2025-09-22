# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903004");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-03-26 16:40:40 +0530 (Mon, 26 Mar 2012)");
  script_cve_id("CVE-2011-3049", "CVE-2011-3052", "CVE-2011-3053", "CVE-2011-3054",
                "CVE-2011-3055", "CVE-2011-3056", "CVE-2011-3057", "CVE-2011-3051",
                "CVE-2011-3050", "CVE-2011-3045");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome Multiple Vulnerabilities (Mar 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48512/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52674");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026841");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/03/stable-channel-update_21.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 17.0.963.83 on Windows");
  script_tag(name:"insight", value:"The flaws are due to:

  - Not properly restrict the extension web request API.

  - Memory corruption in WebGL canvas handling.

  - Use-after-free in block splitting.

  - An error in WebUI privilege implementation which fails to properly perform
    isolation.

  - Prompt in the browser native UI for unpacked extension installation.

  - Cross-origin violation with magic iframe.

  - An invalid read error exists within v8.

  - A use-after-free error exists when handling CSS cross-fade.

  - A use-after-free error exists when handling the first letter.

  - An error exists in the bundled version of libpng.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 17.0.963.83 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"17.0.963.83")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);

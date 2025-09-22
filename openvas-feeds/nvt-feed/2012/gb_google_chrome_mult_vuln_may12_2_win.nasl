# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903030");
  script_version("2025-03-06T05:38:27+0000");
  script_cve_id("CVE-2011-3103", "CVE-2011-3104", "CVE-2011-3105", "CVE-2011-3106",
                "CVE-2011-3107", "CVE-2011-3108", "CVE-2011-3110", "CVE-2011-3111",
                "CVE-2011-3112", "CVE-2011-3113", "CVE-2011-3114", "CVE-2011-3115");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-05-25 14:51:26 +0530 (Fri, 25 May 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - 02 - (May 2012) - Windows");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 19.0.1084.52 on Windows");
  script_tag(name:"insight", value:"The flaws are due to

  - An unspecified error exists in the v8 garbage collection, plug-in
    JavaScript bindings.

  - A use-after-free error exists in the browser cache, first-letter handling
    and with encrypted PDF.

  - An out-of-bounds read error exists in Skia.

  - An error with websockets over SSL can be exploited to corrupt memory.

  - An invalid read error exists in v8.

  - An invalid cast error exists with colorspace handling in PDF.

  - An error with PDF functions can be exploited to cause a buffer overflow.

  - A type corruption error exists in v8.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 19.0.1084.52 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49277/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53679");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027098");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/05/stable-channel-update_23.html");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"19.0.1084.52")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"19.0.1084.52");
  security_message(port:0, data:report);
}

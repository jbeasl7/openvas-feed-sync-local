# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805457");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-3335", "CVE-2015-3334", "CVE-2015-3333", "CVE-2015-1249",
                "CVE-2015-1247", "CVE-2015-1246", "CVE-2015-1244", "CVE-2015-1242",
                "CVE-2015-1241", "CVE-2015-1240", "CVE-2015-1238", "CVE-2015-1237",
                "CVE-2015-1236", "CVE-2015-1235", "CVE-2015-3336");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-04-21 18:18:54 +0530 (Tue, 21 Apr 2015)");
  script_name("Google Chrome Multiple Vulnerabilities-02 (Apr 2015) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Missing address space usage limitation in the NaCl process.

  - Permissions for camera and microphone are merged into a single 'Media'
  permission instead of treated as two separate permission.

  - Flaw in the 'SearchEngineTabHelper::OnPageHasOSDD' function in
  ui/search_engines/search_engine_tab_helper.cc script that is triggered when
  handling URLs for OpenSearch descriptor.

  - An unspecified out-of-bounds read flaw in Blink.

  - A flaw related to WebSocket connections as HSTS
  (HTTP Strict Transport Security) is not enforced.

  - A type confusion flaw in the 'ReduceTransitionElementsKind' function in
  hydrogen-check-elimination.cc script related to HTransitionElementsKind
  handling.

  - A Tap-Jacking flaw that is triggered as certain synthetic Tap events aren't
  preceded by TapDown events.

  - An unspecified out-of-bounds read flaw in WebGL related to handling of ES3
  commands.

  - An unspecified out-of-bounds write flaw in Skia.

  - A use-after-free error in content/renderer/render_frame_impl.cc script.

  - A flaw in the 'MediaElementAudioSourceNode::process' function in
  modules/webaudio/MediaElementAudioSourceNode.cpp script.

  - An unspecified flaw in the HTML Parser.

  - Multiple unspecified Vulnerabilities

  - Browser does not confirm with the user before setting
  CONTENT_SETTINGS_TYPE_FULLSCREEN and CONTENT_SETTINGS_TYPE_MOUSELOCK.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security restrictions, conduct row-hammer attacks,
  obtain sensitive data, trigger unintended UI actions via crafted dimension,
  cause a denial of service and other unspecified impacts.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  42.0.2311.90 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  42.0.2311.90 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/04/stable-channel-update_14.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72715");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74221");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"42.0.2311.90"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     42.0.2311.90'  + '\n';
  security_message(data:report);
  exit(0);
}

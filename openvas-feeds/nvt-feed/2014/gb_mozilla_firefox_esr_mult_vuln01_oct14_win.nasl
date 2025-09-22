# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804942");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-1586", "CVE-2014-1585", "CVE-2014-1583", "CVE-2014-1581",
                "CVE-2014-1578", "CVE-2014-1577", "CVE-2014-1576", "CVE-2014-1574");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-10-20 12:07:41 +0530 (Mon, 20 Oct 2014)");

  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 (Oct 2014) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Alarm API which does not properly restrict toJSON calls.

  - An error when handling video sharing within a WebRTC session running within an
    iframe.

  - An error when handling camera recording within an iframe related to site
    navigation.

  - An use-after-free error when handling text layout related to DirectionalityUtils.

  - An out-of-bounds error within the 'get_tile' function when buffering WebM
    format video containing frames.

  - An out-of-bounds error within 'mozilla::dom::OscillatorNodeEngine::ComputeCustom'
    method when interacting with custom waveforms.

  - An error within the 'nsTransformedTextRun' class when handling capitalization
    style changes during CSS parsing.

  - Other unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  disclose potentially sensitive information, bypass certain security restrictions,
  conduct denial-of-service attack and compromise a user's system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR 31.x before 31.2 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 31.2
  or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59643/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70424");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70436");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70440");
  script_xref(name:"URL", value:"http://msisac.cisecurity.org/advisories/2014/2014-088.cfm");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-82.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-81.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-76.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^31\.")
{
  if((version_in_range(version:vers, test_version:"31.0", test_version2:"31.1")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

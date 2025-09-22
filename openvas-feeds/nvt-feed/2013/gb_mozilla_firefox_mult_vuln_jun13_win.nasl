# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903214");
  script_version("2025-03-05T05:38:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1683", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686",
                "CVE-2013-1687", "CVE-2013-1688", "CVE-2013-1690", "CVE-2013-1692",
                "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1695", "CVE-2013-1696",
                "CVE-2013-1697", "CVE-2013-1698", "CVE-2013-1699", "CVE-2013-1700",
                "CVE-2013-1682", "CVE-2013-1689");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 18:25:57 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-06-26 16:34:51 +0530 (Wed, 26 Jun 2013)");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Jun 2013) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60768");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60773");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60776");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60778");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60779");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60784");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60785");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60787");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60788");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60789");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60790");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60791");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028702");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-50/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=817219");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code, obtain potentially sensitive information, gain escalated privileges, bypass security
  restrictions, and perform unauthorized actions. Other attacks may also be possible.");

  script_tag(name:"affected", value:"Mozilla Firefox before version 22.0 on Windows.");

  script_tag(name:"insight", value:"The following flaws exist:

  - PreserveWrapper does not handle lack of wrapper

  - Error in processing of SVG format images with filters to read pixel values

  - Does not prevent inclusion of body data in XMLHttpRequest HEAD request

  - Does not properly handle onreadystatechange events in conjunction with page reloading

  - Profiler parses untrusted data during UI rendering

  - System Only Wrapper (SOW) and Chrome Object Wrapper (COW), does not restrict XBL user-defined
  functions

  - Use-after-free vulnerability in 'nsIDocument::GetRootElement' and
  'mozilla::dom::HTMLMediaElement::LookupMediaElementURITable' functions

  - Maintenance Service does not properly handle inability to launch the Mozilla Updater executable
  file

  - Multiple unspecified vulnerabilities in the browser engine

  - Internationalized Domain Name (IDN) does not properly handle the .com, .name, and .net top-level
  domains

  - Does not properly implement DocShell inheritance behavior for sandbox attribute of an IFRAME
  element

  - 'getUserMedia' permission references the URL of top-level document instead of a specific page

  - XrayWrapper does not properly restrict use of DefaultValue for method calls

  - Does not properly enforce the X-Frame-Options protection mechanism

  - Crash @xul!nsDOMEvent::GetTargetFromFrame on poison value");

  script_tag(name:"solution", value:"Update to version 22.0 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"22.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"22.0", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);

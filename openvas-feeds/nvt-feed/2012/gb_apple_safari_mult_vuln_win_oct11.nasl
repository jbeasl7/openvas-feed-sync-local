# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903029");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2011-3229", "CVE-2011-1440", "CVE-2011-2338", "CVE-2011-2339",
                "CVE-2011-2341", "CVE-2011-2351", "CVE-2011-2352", "CVE-2011-2354",
                "CVE-2011-2356", "CVE-2011-2359", "CVE-2011-2788", "CVE-2011-2790",
                "CVE-2011-2792", "CVE-2011-2797", "CVE-2011-2799", "CVE-2011-2809",
                "CVE-2011-2811", "CVE-2011-2813", "CVE-2011-2814", "CVE-2011-2815",
                "CVE-2011-2816", "CVE-2011-2817", "CVE-2011-2818", "CVE-2011-2820",
                "CVE-2011-2823", "CVE-2011-2827", "CVE-2011-2831", "CVE-2011-3232",
                "CVE-2011-3233", "CVE-2011-3234", "CVE-2011-3235", "CVE-2011-3236",
                "CVE-2011-3237", "CVE-2011-3238", "CVE-2011-3239", "CVE-2011-3241",
                "CVE-2011-2800", "CVE-2011-2805", "CVE-2011-2819", "CVE-2011-3243");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-05-24 18:22:12 +0530 (Thu, 24 May 2012)");
  script_name("Apple Safari Multiple Vulnerabilities (Oct 2011) - Windows");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48479");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48960");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49279");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49658");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49850");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50088");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50163");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51032");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/Security-announce/2011/Oct/msg00004.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to opening a maliciously
  crafted files, which leads to an unexpected application termination or arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Safari versions prior to 5.1.1 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to

  - A directory traversal issue existed in the handling of 'safari-extension://'
  URLs.

  - A policy issue existed in the handling of 'file://' URLs.

  - An uninitialized memory access issue existed in the handling of SSL
  certificates.

  - Multiple memory corruption issues existed in WebKit.

  - A cross origin issue existed in the handling of the beforeload event,
  'window.open' method, 'document.documentURI' property and inactive DOM
  windows in webkit.

  - A logic issue existed in the handling of cookies in Private Browsing mode.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.1.1 or later.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.34.51.22")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.1.1 (5.34.51.22)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

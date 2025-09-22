# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805456");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-1212", "CVE-2015-1211", "CVE-2015-1210", "CVE-2015-1209");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-02 12:58:34 +0530 (Fri, 02 Jan 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Feb 2015) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple unspecified vulnerabilities in Google Chrome.

  - The 'OriginCanAccessServiceWorkers' function in
    content/browser/service_worker/service_worker_dispatcher_host.cc script
    does not properly restrict the URI scheme during a ServiceWorker registration.

  - The 'V8ThrowException::createDOMException' function in
    bindings/core/v8/V8ThrowException.cpp script in the V8 bindings in Blink does
    not properly consider frame access restrictions during the throwing of an
    exception.

  - A use-after-free flaw in the 'VisibleSelection::nonBoundaryShadowTreeRootNode'
    function in editing/VisibleSelection.cpp script is triggered when a selection's
    anchor is a shadow root.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers gain elevated privileges, bypass cross-origin policies, to cause a
  denial of service or possibly have unspecified other impact via different
  crafted dimensions.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  40.0.2214.111 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  40.0.2214.111 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/02/stable-update.html");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"40.0.2214.111"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
             'Fixed version:     40.0.2214.111'  + '\n';
  security_message(data:report);
  exit(0);
}

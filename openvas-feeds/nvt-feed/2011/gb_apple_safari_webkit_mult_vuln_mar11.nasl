# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801867");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_cve_id("CVE-2011-0160", "CVE-2011-0161", "CVE-2011-0163",
                "CVE-2011-0166", "CVE-2011-0167", "CVE-2011-0169");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Apple Safari Webkit Multiple Vulnerabilities (Mar 2011)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4566");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46808");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46811");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46814");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46816");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43696");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0641");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011/mar/msg00004.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose potentially
  sensitive information, conduct cross-site scripting and spoofing attacks, and compromise a user's system.");

  script_tag(name:"affected", value:"Apple Safari versions prior to 5.0.4.");

  script_tag(name:"insight", value:"- An error in the WebKit component when handling redirects during HTTP Basic
    Authentication can be exploited to disclose the credentials to another site.

  - An error in the WebKit component when handling the Attr.style accessor can
    be exploited to inject an arbitrary Cascading Style Sheet (CSS) into another
    document.

  - A type checking error in the WebKit component when handling cached resources
    can be exploited to poison the cache and prevent certain resources from
    being requested.

  - An error in the WebKit component when handling HTML5 drag and drop
    operations across different origins can be exploited to disclose certain
    content to another site.

  - An error in the tracking of window origins within the WebKit component can
    be exploited to disclose the content of files to a remote server.

  - Input passed to the 'window.console._inspectorCommandLineAPI' property
    while browsing using the Web Inspector is not properly sanitised before
    being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.0.4 or later.");

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

if(version_is_less(version:vers, test_version:"5.33.20.27")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.0.4 (5.33.20.27)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

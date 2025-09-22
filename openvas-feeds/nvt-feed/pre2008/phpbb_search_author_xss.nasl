# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13840");
  script_version("2024-08-02T15:38:45+0000");
  script_tag(name:"last_modification", value:"2024-08-02 15:38:45 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0730", "CVE-2004-2054", "CVE-2004-2055");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162128/http://www.securityfocus.com/bid/10738");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162128/http://www.securityfocus.com/bid/10753");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162128/http://www.securityfocus.com/bid/10754");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162128/http://www.securityfocus.com/bid/10883");
  script_xref(name:"OSVDB", value:"8164");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("phpBB < 2.0.10 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"solution", value:"Update to version 2.0.10 or later.");

  script_tag(name:"summary", value:"phpBB is prone to multiple vulnerabilities.");

  script_tag(name:"affected", value:"phpBB prior to version 2.0.10.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2004-0730: Multiple cross-site scripting (XSS) vulnerabilities

  - CVE-2004-2054: A HTTP response splitting vulnerability which permits the injection of CRLF
  characters in the HTTP headers.

  - CVE-2004-2055: A flaw that allows a remote XSS attack. This flaw exists because the application
  does not validate user-supplied input in the 'search_author' parameter.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.0.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

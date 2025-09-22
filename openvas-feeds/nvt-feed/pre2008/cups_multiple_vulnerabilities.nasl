# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16141");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270", "CVE-2005-2874");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 1.1.23 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Gain a shell remotely");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - The is_path_absolute function in scheduler/client.c for the daemon in CUPS allows remote
  attackers to cause a denial of service (CPU consumption by tight loop) via a '..\..' URL in an
  HTTP request.

  - A remotely exploitable buffer overflow in the 'hpgltops' filter that enable specially crafted
  HPGL files can execute arbitrary commands as the CUPS 'lp' account.

  - A local user may be able to prevent anyone from changing his or her password until a temporary
  copy of the new password file is cleaned up ('lppasswd' flaw).

  - A local user may be able to add arbitrary content to the password file by closing the stderr
  file descriptor while running lppasswd (lppasswd flaw).

  - A local attacker may be able to truncate the CUPS password file, thereby denying service to
  valid clients using digest authentication. (lppasswd flaw).

  - The application applies ACLs to incoming print jobs in a case-sensitive fashion. Thus, an
  attacker can bypass restrictions by changing the case in printer names when submitting jobs.
  [Fixed in 1.1.21.]");

  script_tag(name:"affected", value:"CUPS version 1.0.4 through 1.1.22.");

  script_tag(name:"solution", value:"Update to version 1.1.23 or later.");

  script_xref(name:"OSVDB", value:"12439");
  script_xref(name:"OSVDB", value:"12453");
  script_xref(name:"OSVDB", value:"12454");
  script_xref(name:"FLSA", value:"FEDORA-2004-908");
  script_xref(name:"FLSA", value:"FEDORA-2004-559");
  script_xref(name:"FLSA", value:"FEDORA-2004-560");
  script_xref(name:"GLSA", value:"GLSA-200412-25");

  script_xref(name:"URL", value:"http://www.cups.org/str.php?L700");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11968");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12007");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12200");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14265");
  script_xref(name:"URL", value:"http://www.cups.org/str.php?L1024");
  script_xref(name:"URL", value:"http://www.cups.org/str.php?L1023");
  script_xref(name:"URL", value:"http://www.cups.org/str.php?L1042");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.1.23" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.23" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

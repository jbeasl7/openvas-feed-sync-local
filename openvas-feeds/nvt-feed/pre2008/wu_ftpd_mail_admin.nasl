# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:washington_university:wu-ftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14371");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2003-1327");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8668");
  script_xref(name:"OSVDB", value:"2594");
  script_name("wu-ftpd < 2.6.3 'MAIL_ADMIN' Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_dependencies("gb_wu-ftpd_detect.nasl");
  script_mandatory_keys("wu-ftpd/installed");

  script_tag(name:"summary", value:"The remote Wu-FTPd server seems to be
  vulnerable to a remote flaw.");

  script_tag(name:"insight", value:"This version fails to properly check bounds
  on a pathname when Wu-Ftpd is compiled with MAIL_ADMIN enabled resulting in a
  buffer overflow. With a specially crafted request, an attacker can possibly
  execute arbitrary code as the user Wu-Ftpd runs as (usually root) resulting
  in a loss of integrity, and/or availability.

  It should be noted that this vulnerability is not present within the default
  installation of Wu-Ftpd.

  The server must be configured using the 'MAIL_ADMIN' option to notify an
  administrator when a file has been uploaded.");

  script_tag(name:"solution", value:"Update to version 2.6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( egrep( pattern:"^2\.6\.[0-2]$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.6.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

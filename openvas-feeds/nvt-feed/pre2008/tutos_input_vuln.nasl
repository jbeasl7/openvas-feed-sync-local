# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tutos:tutos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14793");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10129");
  script_xref(name:"OSVDB", value:"5326");
  script_cve_id("CVE-2003-0481", "CVE-2003-0482");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Tutos < 1.1.20040412 Input Validation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("sw_tutos_detect.nasl");
  script_mandatory_keys("tutos/installed");

  script_tag(name:"solution", value:"Update to version 1.1.20040412 or later.");

  script_tag(name:"summary", value:"Tutos is prone to an input validation vulnerability.");

  script_tag(name:"insight", value:"The remote version of this software is vulnerable to multiple
  input validation flaws which may allow an authenticated user to perform a cross site scripting
  attack, path disclosure attack or a SQL injection against the remote service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( egrep( pattern:"(0\..*|1\.(0\.|1\.(2003|20040[1-3]|2004040[0-9]|2004041[01])))", string:vers ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

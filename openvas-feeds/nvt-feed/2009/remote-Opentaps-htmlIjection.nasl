# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:opentaps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101022");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-04-24 21:45:26 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-6589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21702");
  script_name("Opentaps ERP + CRM Search_String Parameter HTML Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Web application abuses");
  script_dependencies("remote-detect-Opentaps_ERP_CRM.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("OpentapsERP/installed");

  script_tag(name:"solution", value:"Download the latest release from the opentaps website.");

  script_tag(name:"summary", value:"The running Opentaps ERP + CRM is prone to an HTML injection
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("revisions-lib.inc");
include("misc_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( port:port, cpe:CPE ) ) exit( 0 );

if( revcomp( a:vers, b:"0.9.3" ) <= 0 ) {
  report = "The current Opentaps version " + vers + " is affected by a Search_String Parameter HTML injection vulnerability.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
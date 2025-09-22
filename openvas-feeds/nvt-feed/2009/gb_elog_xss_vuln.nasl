# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:stefan_ritt:elog_web_logbook";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900939");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-7206");
  script_name("ELOG Logbook XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_elog_detect.nasl");
  script_mandatory_keys("ELOG/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/40124");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27526");
  script_xref(name:"URL", value:"https://midas.psi.ch/elog/download/ChangeLog");

  script_tag(name:"impact", value:"Attackers can exploit this issue to steal cookie-based authentication
  credentials by conducting Cross-Site Scripting attacks on the affected system.");

  script_tag(name:"affected", value:"ELOG versions prior to 2.7.2.");

  script_tag(name:"insight", value:"An error occurs while processing malicious user supplied data passed into
  the 'logbook' module and can be exploited to inject arbitrary HTML and
  script code in the context of the affected application.");

  script_tag(name:"solution", value:"Upgrade ELOG Version to 2.7.2 or later. Please see the
  references for more info.");

  script_tag(name:"summary", value:"ELOG is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

# nb: 2.7.2 => 2.7.2-2012
if( version_is_less( version:vers, test_version:"2.7.2.2012" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.7.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:greenbone:greenbone_security_assistant";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801919");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0650");
  script_name("Greenbone Security Assistant < 2.0.0 CSRF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_greenbone_gsa_http_detect.nasl");
  script_mandatory_keys("greenbone/gsa/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct cross-site
  request forgery attacks.");

  script_tag(name:"affected", value:"Greenbone Security Assistant version prior to 2.0.0.");

  script_tag(name:"insight", value:"The application allows users to perform certain actions via HTTP
  requests without performing any validity checks to verify the requests. This
  can be exploited to execute arbitrary commands in OpenVAS Manager by tricking
  a logged in administrative user into visiting a malicious web site.");

  script_tag(name:"solution", value:"Update Greenbone Security Assistant to version 2.0.0 or later.");

  script_tag(name:"summary", value:"Greenbone Security Assistant is prone to a cross-site request
  forgery (CSRF) vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43092");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65012");
  script_xref(name:"URL", value:"http://www.openvas.org/OVSA20110118.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/515971/100/0/threaded");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800837");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1891");
  script_name("Apache HTTP Server 'mod_deflate' Denial Of Service Vulnerability (Jul 2009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35781");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35623");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1841");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2009-1148.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=509125");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause Denial of Service
  to the legitimate user by CPU consumption.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.2.11 and prior.");

  script_tag(name:"insight", value:"The flaw is due to error in 'mod_deflate' module which can cause a high CPU
  load by requesting large files which are compressed and then disconnecting.");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a Denial of Service vulnerability.");

  script_tag(name:"solution", value:"Update to version 2.2.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"2.2.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.12", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

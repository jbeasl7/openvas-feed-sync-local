# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100858");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-10-19 12:49:22 +0200 (Tue, 19 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2791");
  script_name("Apache HTTP Server 'mod_proxy_http' 2.2.9 for Unix Timeout Handling Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42102");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/3243");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=699841");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100109771"); # nb: According to the vendor advisory: "An information disclosure flaw was found in mod_proxy_http in version 2.2.9 only,"

  script_tag(name:"affected", value:"Apache HTTP Server 2.2.9 on Unix is vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to an information disclosure vulnerability that
  affects the 'mod_proxy_http' module.");

  script_tag(name:"impact", value:"Attackers can leverage this issue to gain access to sensitive
  information that may aid in further attacks.");

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

if( version_is_equal( version:vers, test_version:"2.2.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.10", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

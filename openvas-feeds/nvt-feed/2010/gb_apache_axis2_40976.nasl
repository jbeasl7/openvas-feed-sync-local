# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:axis2";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100814");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1632");
  script_name("Apache Axis2 < 1.5.2 Document Type Declaration Processing Security Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_apache_axis2_http_detect.nasl");
  script_mandatory_keys("apache/axis2/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40976");
  script_xref(name:"URL", value:"http://geronimo.apache.org/2010/07/21/apache-geronimo-v216-released.html");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27019456");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/AXIS2-4450");
  script_xref(name:"URL", value:"https://svn.apache.org/repos/asf/axis/axis2/java/core/security/CVE-2010-1632.pdf");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24027020");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24027019");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg24027503");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg24027502");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21433581");

  script_tag(name:"summary", value:"Apache Axis2 is prone to a security vulnerability that may
  result in information disclosure or denial-of-service (DoS) conditions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information by including local and external files on computers running the vulnerable
  application or by causing denial-of-service conditions. Other attacks are also possible.");

  script_tag(name:"affected", value:"The issue affects versions prior to 1.5.2 and 1.6.");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

path = infos["location"];
vers = infos["version"];

if( version_is_less( version:vers, test_version:"1.5.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.5.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

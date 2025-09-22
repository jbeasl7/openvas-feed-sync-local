# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802678");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2012-5887", "CVE-2012-5886", "CVE-2012-5885");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-11-27 16:27:51 +0530 (Tue, 27 Nov 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Apache Tomcat Multiple Security Bypass Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51138/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56403");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.36");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.36");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.30");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1377807");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1380829");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1392248");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to bypass intended
  access restrictions by sniffing the network for valid requests.");

  script_tag(name:"affected", value:"Apache Tomcat version 5.5.x to 5.5.35, 6.x to 6.0.35 and 7.x to 7.0.29.");

  script_tag(name:"insight", value:"The flaws are due to error in HTTP digest access authentication
  implementation, which does not properly validate for,

  - stale nonce values in conjunction with enforcement of proper credentials

  - caches information about the authenticated user within the session state

  - cnonce values instead of nonce and nc values.");

  script_tag(name:"summary", value:"Apache Tomcat Server is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"solution", value:"Apply patch or upgrade Apache Tomcat to 5.5.36, 6.0.36, 7.0.30 or later.");

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

if( version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.35" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.35" ) ||
    version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.29" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.36/6.0.36/7.0.30", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
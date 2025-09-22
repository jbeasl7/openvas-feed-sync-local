# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800989");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0289");
  script_name("DokuWiki Multiple CSRF Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38205");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0150");
  script_xref(name:"URL", value:"http://bugs.splitbrain.org/index.php?do=details&task_id=1853");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to conduct cross site request
  forgery attacks via unknown vectors.");
  script_tag(name:"affected", value:"Dokuwiki versions prior to 2009-12-25c");
  script_tag(name:"insight", value:"The flaws are due to error in 'ACL' Manager plugin (plugins/acl/ajax.php) that
  allows users to perform certain actions via HTTP requests without performing
  any validity checks.");
  script_tag(name:"solution", value:"Update to version 2009-12-25c or later.");
  script_tag(name:"summary", value:"Dokuwiki is prone to multiple Cross Site Scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.splitbrain.org/go/dokuwiki");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2009-12-25c" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2009-12-25c" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

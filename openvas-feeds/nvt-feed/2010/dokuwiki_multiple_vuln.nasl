# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100451");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2010-0287");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-18 11:34:48 +0100 (Mon, 18 Jan 2010)");
  script_name("DokuWiki < 2009-12-25b Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37821");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37820");

  script_tag(name:"summary", value:"DokuWiki is prone to an information disclosure vulnerability and
  to multiple security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting these issues may allow attackers to determine whether
  certain files reside on the affected computer. Information obtained may lead to further attacks.
  Unauthenticated attackers can leverage these issues to change or delete wiki permissions.");

  script_tag(name:"affected", value:"These issues affect DokuWiki version 2009-12-25. Other
  versions may be vulnerable as well.");

  script_tag(name:"solution", value:"Reports indicate that updates are available, but Symantec has
  not confirmed this information. Please see the references and contact the vendor for details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2009-12-25b" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2009-12-25b" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

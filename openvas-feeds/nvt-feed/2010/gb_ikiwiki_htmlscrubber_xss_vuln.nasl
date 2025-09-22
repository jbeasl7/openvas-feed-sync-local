# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800746");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_cve_id("CVE-2010-1195");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ikiwiki 'htmlscrubber' Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://ikiwiki.info/download/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38983");
  script_xref(name:"URL", value:"http://ikiwiki.info/security/#index36h2");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0662");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_ikiwiki_consolidation.nasl");
  script_mandatory_keys("ikiwiki/detected");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary script code,
  in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"ikiwiki versions 2.x through 2.53.4 and 3.x through 3.20100311");
  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the htmlscrubber component
  when processing 'data:image/svg+xml' URIs.");
  script_tag(name:"solution", value:"Upgrade to ikiwiki version 2.53.5 or 3.20100312");
  script_tag(name:"summary", value:"Ikiwiki is prone to a cross-site scripting (XSS) vulnerability.");

  exit(0);
}

CPE = "cpe:/a:ikiwiki:ikiwiki";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit( 0 );
if(!version = get_app_version(cpe:CPE, port:port)) exit( 0 );

if(version_in_range(version:version, test_version:"2.0", test_version2:"2.53.4")){
  report = report_fixed_ver(installed_version:version, fixed_version:"2.53.5");
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:version, test_version:"3.0", test_version2:"3.20100311")){
  report = report_fixed_ver(installed_version:version, fixed_version:"3.20100312");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

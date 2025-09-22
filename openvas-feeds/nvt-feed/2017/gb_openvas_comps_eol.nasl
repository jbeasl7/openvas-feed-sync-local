# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108197");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-07-26 15:00:00 +0200 (Wed, 26 Jul 2017)");
  script_name("OpenVAS Framework / GVM Components End of Life (EOL) Detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_greenbone_gsa_http_detect.nasl", "gb_openvas_manager_detect.nasl", "gb_greenbone_os_consolidation.nasl");
  script_mandatory_keys("openvas_gvm/framework_component/detected");
  script_exclude_keys("greenbone/gos/detected"); # nb: GOS is already covered via 2013/gb_os_eol.nasl

  script_xref(name:"URL", value:"https://forum.greenbone.net/t/greenbone-community-edition-21-04-end-of-life/13837");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-21-04-end-of-life-initial-release-2021-04-16/8942");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-20-08-end-of-life-initial-release-2020-08-12/6312");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-11-end-of-life-initial-release-2019-10-14/3674");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-10-end-of-life-initial-release-2019-04-05/208");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-9-end-of-life-initial-release-2017-03-07/211");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2018-March/000216.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2016-May/000194.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2015-April/000181.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2014-August/000166.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2013-August/000155.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2012-September/000143.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2011-June/000127.html");
  script_xref(name:"URL", value:"http://lists.wald.intevation.org/pipermail/openvas-announce/2009-December/000084.html");

  script_tag(name:"summary", value:"The version of the OpenVAS framework / Greenbone Vulnerability
  Management (GVM) component on the remote host has reached the End of Life (EOL) and should not be
  used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"impact", value:"An EOL version of an OpenVAS framework / GVM component is not
  receiving any security updates from the vendor. Unfixed security vulnerabilities might be
  leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the OpenVAS framework / GVM component version on the
  remote host to a still supported version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("list_array_func.inc");
include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");

if( get_kb_item( "greenbone/gos/detected" ) )
  exit( 0 ); # nb: GOS is already covered via 2013/gb_os_eol.nasl

cpe_list = make_list( "cpe:/a:greenbone:greenbone_security_assistant", "cpe:/a:openvas:openvas_manager", "cpe:/a:greenbone:greenbone_vulnerability_manager" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! infos = get_app_version_and_location( cpe:cpe, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];

if( ret = product_reached_eol( cpe:cpe, version:version ) ) {

  location = infos["location"];

  if( "security_assistant" >< cpe )
    prod_name = "Greenbone Security Assistant";
  else if( "openvas_manager" >< cpe )
    prod_name = "OpenVAS Manager";
  else if( "greenbone_vulnerability_manager" >< cpe )
    prod_name = "Greenbone Vulnerability Manager";
  else
    prod_name = "OpenVAS";

  report = eol_build_message( name:prod_name,
                              cpe:cpe,
                              version:version,
                              location:location,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113139");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-03-20 12:40:00 +0100 (Tue, 20 Mar 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-12 12:43:00 +0000 (Thu, 12 Apr 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-8732");

  script_name("WampServer 3.1.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wampserver_detect.nasl");
  script_mandatory_keys("wampserver/installed");

  script_tag(name:"summary", value:"WampServer is prone to an XSS vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The XSS is possible through the virtual_del parameter.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to create a crafted link to
  inject arbitrary HTML and JavaScript into the target website.");
  script_tag(name:"affected", value:"WampServer through version 3.1.1.");
  script_tag(name:"solution", value:"Update to version 3.1.2.");

  script_xref(name:"URL", value:"http://forum.wampserver.com/read.php?2,138295,150615,page=6#msg-150615");

  exit(0);
}

CPE = "cpe:/a:wampserver:wampserver";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.1.2" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

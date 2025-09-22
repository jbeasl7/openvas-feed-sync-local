# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105169");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-14 11:37:01 +0100 (Wed, 14 Jan 2015)");

  script_name("Snom < 8.7.5.15 Multiple Vulnerabilities");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_snom_consolidation.nasl");
  script_mandatory_keys("snom/detected");

  script_xref(name:"URL", value:"http://wiki.snom.com/8.7.5.15_OpenVPN_Security_Update");

  script_tag(name:"summary", value:"The remote Snom device is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"insight", value:"Several issues existed in actionURLs and java script handling that would
  have allowed an attacker to get access to administrations rights. With administrations rights an attacker can
  misuse the OpenVPN support to upload malware or spoof a VPN tunnels.");

  script_tag(name:"impact", value:"A remote attacker may be able to gain administration rights, spoof a VPN tunnel,
  place malware and execute arbitrary code.");

  script_tag(name:"affected", value:"Snom devices with firmware < 8.7.5.15.");

  script_tag(name:"solution", value:"Update to a firmware version >= 8.7.5.15.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/h:snom:snom_760",
                      "cpe:/h:snom:snom_720",
                      "cpe:/h:snom:snom_715",
                      "cpe:/h:snom:snom_710",
                      "cpe:/h:snom:snom_870",
                      "cpe:/h:snom:snom_821",
                      "cpe:/h:snom:snom_820",
                      "cpe:/h:snom:snom_370" );

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

vers = infos["version"];

if( version_is_less( version:vers, test_version:"8.7.5.15" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.7.5.15" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

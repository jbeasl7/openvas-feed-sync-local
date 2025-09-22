# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:igniterealtime:openfire";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800718");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 17:43:58 +0000 (Tue, 13 Feb 2024)");

  script_cve_id("CVE-2009-1595", "CVE-2009-1596");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Openfire < 3.6.5 Security Bypass Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_http_detect.nasl");
  script_mandatory_keys("openfire/detected");

  script_tag(name:"summary", value:"Openfire is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- An error exists in the 'jabber:iq:auth' implementation in the
  IQAuthHandler.java File via a modified username element in a passwd_change action.

  - An error due to improper implementation of 'register.password' console configuration settings
  via a passwd_change IQ packet.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker change the
  passwords of arbitrary accounts via a modified username element in a passwd_change action or can
  bypass intended policy and change their own passwords via a passwd_change IQ packet or will let
  the attacker bypass intended policy and change their own passwords via a passwd_change IQ
  packet.");

  script_tag(name:"affected", value:"Openfire prior to version 3.6.5.");

  script_tag(name:"solution", value:"Update to version 3.6.5 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34976");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34804");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34984");
  script_xref(name:"URL", value:"http://www.igniterealtime.org/issues/browse/JM-1532");
  script_xref(name:"URL", value:"http://www.igniterealtime.org/issues/browse/JM-1531");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34984");
  script_xref(name:"URL", value:"http://www.igniterealtime.org/issues/browse/JM-1532");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"3.6.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.6.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

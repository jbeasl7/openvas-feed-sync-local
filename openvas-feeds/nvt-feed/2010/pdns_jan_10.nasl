# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100433");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-01-07 12:29:25 +0100 (Thu, 07 Jan 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4010", "CVE-2009-4009");
  script_name("PowerDNS Recursor Multiple Vulnerabilities (Jan 2010)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37653");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37650");
  script_xref(name:"URL", value:"http://www.powerdns.com/");
  script_xref(name:"URL", value:"http://doc.powerdns.com/powerdns-advisory-2010-02.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508743");

  script_tag(name:"impact", value:"An attacker can exploit the remote cache-poisoning vulnerability to
  divert data from a legitimate site to an attacker-specified site.
  Successful exploits will allow the attacker to manipulate cache data,
  potentially facilitating man-in-the-middle, site-impersonation, or denial-of-
  service attacks.

  Successfully exploiting of the Buffer Overflow vulnerability allows a
  remote attacker to execute arbitrary code with superuser privileges,
  resulting in a complete compromise of the affected computer. Failed
  exploits will cause a denial of service.");
  script_tag(name:"affected", value:"PowerDNS Recursor 3.1.7.1 and earlier are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a remote cache-poisoning vulnerability and to a
  Buffer Overflow Vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"3.1.7.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.1.7.2" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );

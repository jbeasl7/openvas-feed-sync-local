# SPDX-FileCopyrightText: 2008 Tenable Network Security & David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kerio:kerio_mailserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80069");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-1434", "CVE-2003-0487", "CVE-2003-0488");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5507");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7966");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7967");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7968");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8230");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9975");
  script_xref(name:"OSVDB", value:"2159");
  script_xref(name:"OSVDB", value:"4953");
  script_xref(name:"OSVDB", value:"4954");
  script_xref(name:"OSVDB", value:"4955");
  script_xref(name:"OSVDB", value:"4956");
  script_xref(name:"OSVDB", value:"4958");
  script_name("Kerio WebMail < 5.7.7 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Tenable Network Security & David Maciejak");
  script_family("Gain a shell remotely");
  script_dependencies("gb_kerio_mailserver_detect.nasl");
  script_mandatory_keys("KerioMailServer/detected");

  script_tag(name:"solution", value:"Update to version 5.7.7 or later.");

  script_tag(name:"summary", value:"Kerio MailServer is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"There are multiple flaws in this interface which may allow an
  attacker with a valid webmail account on this host to obtain a shell on this host or to perform a
  cross-site-scripting attack against this host with version prior to 5.6.4. Version of MailServer
  prior to 5.6.5 are also prone to a denial of service condition when an incorrect login to the
  admin console occurs. This could cause the server to crash. Version of MailServer prior to 5.7.7
  is prone to a remotely exploitable buffer overrun condition. This vulnerability exists in the spam
  filter component. If successfully exploited, this could permit remote attackers to execute
  arbitrary code in the context of the MailServer software. This could also cause a denial of
  service in the server.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE, version_regex:"^5\." ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.7.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.7.7" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
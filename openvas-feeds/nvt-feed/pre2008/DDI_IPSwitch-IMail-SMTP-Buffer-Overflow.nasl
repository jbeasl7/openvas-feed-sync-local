# SPDX-FileCopyrightText: 2002 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ipswitch:imail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10994");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0039", "CVE-2001-0494");
  script_name("IPSwitch IMail SMTP Buffer Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Digital Defense Inc.");
  script_family("SMTP problems");
  script_dependencies("gb_ipswitch_imail_server_detect.nasl");
  script_mandatory_keys("Ipswitch/IMail/detected");

  script_xref(name:"URL", value:"http://ipswitch.com/support/IMail/patch-upgrades.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2083");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2651");

  script_tag(name:"impact", value:"If an attacker crafts a special buffer and sends it to a remote IMail SMTP server
  it is possible that an attacker can remotely execute code (commands) on the IMail system.");

  script_tag(name:"insight", value:"The vulnerability stems from the IMail SMTP daemon not doing proper bounds checking on
  various input data that gets passed to the IMail Mailing List handler code.");

  script_tag(name:"solution", value:"Download the latest patch from the linked references.");

  script_tag(name:"summary", value:"A vulnerability exists within IMail that allows remote attackers to gain SYSTEM level
  access to servers running IMail's SMTP daemon (versions 6.06 and below).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit(0);

if( version_is_less_equal( version:version, test_version:"6.06" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See references" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
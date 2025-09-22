# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:torrenttrader:torrenttrader_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100181");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_cve_id("CVE-2008-1173");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("TorrentTrader Classic 'msg' Parameter HTML Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_torrent_trader_classic_detect.nasl");
  script_mandatory_keys("torrenttraderclassic/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28082");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?group_id=98584&release_id=545219");

  script_tag(name:"solution", value:"This issue has been addressed in the revision 25/03/08 of Torrent Classic 1.08.
  Update to Torrent Classic 1.09.");

  script_tag(name:"impact", value:"Attacker-supplied HTML or JavaScript code could run in the context of the affected site,
  potentially allowing the attacker to steal cookie-based authentication credentials and to control how the site
  is rendered to the user. Other attacks are also possible.");

  script_tag(name:"summary", value:"TorrentTrader is prone to an HTML-injection vulnerability because it
  fails to adequately sanitize user-supplied input.");

  script_tag(name:"affected", value:"TorrentTrader Classic 1.08 is affected. Other versions may also be vulnerable.");

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

if( version_is_equal( version:vers, test_version:"1.08" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.09" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

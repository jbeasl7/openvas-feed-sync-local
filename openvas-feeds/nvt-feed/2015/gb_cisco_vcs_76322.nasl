# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105335");
  script_version("2024-02-21T14:36:44+0000");
  script_tag(name:"last_modification", value:"2024-02-21 14:36:44 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-08-27 15:44:02 +0200 (Thu, 27 Aug 2015)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2015-4303", "CVE-2015-4316", "CVE-2015-4317", "CVE-2015-4318",
                "CVE-2015-4319", "CVE-2015-4320");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Cisco TelePresence Video Communication Server (VCS) Multiple Vulnerabilities (Oct 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_vcs_consolidation.nasl");
  script_mandatory_keys("cisco/vcs/detected");

  script_tag(name:"summary", value:"Cisco TelePresence Video Communication Server Expressway is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2015-4303: Command injection (Cisco-SA-20150812-CVE-2015-4303)

  - CVE-2015-4316: Insufficient validation of the registering phone line
  (Cisco-SA-20150813-CVE-2015-4316)

  - CVE-2015-4317: Denial of Service (DoS) (Cisco-SA-20150813-CVE-2015-4317)

  - CVE-2015-4318: Denial of Service (DoS) (Cisco-SA-20150813-CVE-2015-4318)

  - CVE-2015-4319: Insufficient enforcement in the authorization process
  (Cisco-SA-20150814-CVE-2015-4319)

  - CVE-2015-4320: Information disclosure (Cisco-SA-20150813-CVE-2015-4320)");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server Expressway
  version X8.5.2.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv40528");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76326");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76347");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76366");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76353");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76351");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76350");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv12333");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv40396");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv40469");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv12338");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv12340");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version =~ "^8\.5\.2($|[^0-9])" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"Ask the vendor" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );

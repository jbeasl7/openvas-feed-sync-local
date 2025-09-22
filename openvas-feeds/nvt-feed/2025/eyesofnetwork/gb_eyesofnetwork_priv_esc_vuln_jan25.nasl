# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118680");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-01-08 14:13:37 +0000 (Wed, 08 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2022-41572");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Eyes Of Network (EON) <= 5.3.11 Privilege Escalation Vulnerability (GHSA-3wv8-q6g7-7frh)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_consolidation.nasl");
  script_mandatory_keys("eyesofnetwork/detected");

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Privilege escalation can be accomplished on the server because
  nmap can be run as root. The attacker achieves total control over the server.");

  script_tag(name:"affected", value:"Eyes Of Network through version 5.3.11.");

  script_tag(name:"solution", value:"No known solution is available as of 08th January, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-3wv8-q6g7-7frh");
  script_xref(name:"URL", value:"https://github.com/EyesOfNetworkCommunity/eonweb/issues/120");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less_equal( version:version, test_version:"5.3.11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:centreon:centreon";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103338");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Centreon 'command_name' Parameter RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50568");
  script_xref(name:"URL", value:"http://www.centreon.com/");
  script_xref(name:"URL", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2011-017.txt");

  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-11-16 09:31:56 +0100 (Wed, 16 Nov 2011)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_centreon_web_http_detect.nasl");
  script_mandatory_keys("centreon_web/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Centreon is prone to a remote command-injection vulnerability.

Attackers can exploit this issue to execute arbitrary commands in the context of the application.

Centreon 2.3.1 is affected. Other versions may also be vulnerable.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: vers, test_version: "2.3.1")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 2.3.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

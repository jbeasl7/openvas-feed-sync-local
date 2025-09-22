# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:communigate:communigate_pro";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100242");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("CommuniGate Pro Web Mail URI Parsing HTML Injection Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_communigatepro_consolidation.nasl");
  script_mandatory_keys("communigatepro/detected");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor released an update to address this issue, please see the
  references for more information.");

  script_tag(name:"summary", value:"CommuniGate Pro is prone to an HTML-injection vulnerability because it
  fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to execute HTML and script code in the context of the affected site,
  to steal cookie-based authentication credentials, or to control how the site is rendered to the user. Other
  attacks are also possible.");

  script_tag(name:"affected", value:"Versions prior to CommuniGate Pro 5.2.15 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35783");
  script_xref(name:"URL", value:"http://www.communigate.com/cgatepro/History52.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/505211");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.15");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100471");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-01-28 18:48:47 +0100 (Thu, 28 Jan 2010)");
  script_cve_id("CVE-2010-0300");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("ircd-ratbox 'HELP' Command Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37979");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("ircd.nasl");
  script_require_ports("Services/irc", 6667);
  script_mandatory_keys("ircd/banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for
  details.");

  script_tag(name:"summary", value:"The 'ircd-ratbox' daemon is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to deny service to legitimate
  users.");

  script_tag(name:"affected", value:"This issue affects ircd-ratbox 2.2.8. Other versions may also
  be affected.");

  exit(0);
}

include("version_func.inc");
include("port_service_func.inc");

port = service_get_port(default:6667, proto:"irc");

banner = get_kb_item("irc/banner/" + port);
if(!banner || "ratbox" >!< banner)
  exit(0);

version = eregmatch(pattern:"ircd-ratbox-([0-9.]+)", string:banner);
if(isnull(version[1]))
  exit(0);

if(version_is_less_equal(version:version[1], test_version:"2.2.8")) {
  report = report_fixed_ver(installed_version:version[1], vulnerable_range:"Less than or equal to 2.2.8");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

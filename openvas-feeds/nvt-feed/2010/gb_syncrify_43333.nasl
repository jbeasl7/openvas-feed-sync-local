# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100820");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)");

  script_name("Syncrify Multiple Remote Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43333");
  script_xref(name:"URL", value:"http://web.synametrics.com/SyncrifyVersionHistory.htm");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_syncrify_detect.nasl");
  script_require_ports("Services/www", 5800);
  script_mandatory_keys("syncrify/app/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Syncrify is prone to multiple remote security bypass vulnerabilities.");

  script_tag(name:"impact", value:"Exploiting these issues may allow a remote attacker to bypass certain
  security restrictions and perform unauthorized actions.");

  script_tag(name:"affected", value:"Syncrify 2.1 Build 415 and prior are affected.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:5800);

if(vers = get_version_from_kb(port:port, app:"syncrify")) {
  if(version_is_less_equal(version: vers, test_version: "2.1.415")) {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 2.1.415");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);

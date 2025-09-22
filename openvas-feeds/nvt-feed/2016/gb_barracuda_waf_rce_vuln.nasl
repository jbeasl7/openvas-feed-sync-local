# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:barracuda:web_application_firewall";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106150");
  script_version("2024-01-30T14:37:03+0000");
  script_tag(name:"last_modification", value:"2024-01-30 14:37:03 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"creation_date", value:"2016-07-25 12:59:46 +0700 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Barracuda Web Application Firewall < 8.0.1.008 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_barracuda_web_application_firewall_consolidation.nasl");
  script_mandatory_keys("barracuda/web_application_firewall/detected");

  script_tag(name:"summary", value:"Barracuda Web Application Firewall is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By sending a specially crafted request an authenticated
  attacker may inject system commands while escalating to root do to relaxed sudo configurations on
  the appliances.");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary system
  commands.");

  script_tag(name:"affected", value:"Barracuda Web Application Firewall version 8.0.1.007 and
  prior.");

  script_tag(name:"solution", value:"Update to version 8.0.1.008 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138020/Barracuda-Web-App-Firewall-Load-Balancer-Remote-Root.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "8.0.1.007")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1.008");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:barracuda:web_application_firewall";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100420");
  script_version("2024-01-30T14:37:03+0000");
  script_tag(name:"last_modification", value:"2024-01-30 14:37:03 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Barracuda Web Application Firewall <= 7.3.1.007 Multiple HTML Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_barracuda_web_application_firewall_consolidation.nasl");
  script_mandatory_keys("barracuda/web_application_firewall/detected");

  script_tag(name:"summary", value:"The Barracuda Web Application Firewall 660 is prone to multiple
  HTML injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attacker-supplied HTML and script code would execute in the
  context of the affected site, potentially allowing the attacker to steal cookie-based
  authentication credentials or to control how the site is rendered to the user. Other attacks are
  also possible.");

  script_tag(name:"affected", value:"Barracuda Web Application Firewall 660 firmware version
  7.3.1.007 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37432");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "7.3.1.007")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port:0, data: report);
  exit(0);
}

exit(0);

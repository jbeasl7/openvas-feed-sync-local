# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:centreon:centreon";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100428");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-01-06 10:44:19 +0100 (Wed, 06 Jan 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4368");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Centreon Authentication Mechanism Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37383");
  script_xref(name:"URL", value:"http://www.centreon.com/Development/changelog-2x.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_centreon_web_http_detect.nasl");
  script_mandatory_keys("centreon_web/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Centreon is prone to a security bypass vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain security
  restrictions and gain unauthorized access to certain functionality, which may lead to further
  attacks.");

  script_tag(name:"affected", value:"Centreon versions prior to 2.1.4.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "2.1.4")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.1.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

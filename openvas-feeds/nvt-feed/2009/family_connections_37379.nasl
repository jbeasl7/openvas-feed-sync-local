# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:haudenschilt:family_connections_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100408");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Family Connections <= 2.1.3 Multiple Input Validation Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37379");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("family_connections_detect.nasl");
  script_mandatory_keys("family_connections/installed");

  script_tag(name:"summary", value:"Family Connections is prone to multiple input-validation
  vulnerabilities, including a local file include (LFI) issue, an arbitrary file-upload issue, and
  multiple SQL injection (SQLi) issues. These issues occur because the application fails to properly
  sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues may allow an unauthorized user to view files and execute
  local scripts, execute arbitrary script code, access or modify data, or exploit latent vulnerabilities in the
  underlying database implementation.");

  script_tag(name:"affected", value:"Family Connections versions 2.1.3 and prior are affected.");

  script_tag(name:"solution", value:"Update to version 2.2 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

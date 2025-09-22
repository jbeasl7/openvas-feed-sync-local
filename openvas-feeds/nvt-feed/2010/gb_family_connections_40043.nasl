# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:haudenschilt:family_connections_cms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100634");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-05-11 20:07:01 +0200 (Tue, 11 May 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Family Connections 2.2.3 Multiple SQLi Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40043");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("family_connections_detect.nasl");
  script_mandatory_keys("family_connections/installed");

  script_tag(name:"summary", value:"Family Connections is prone to multiple SQL injection (SQLi)
  vulnerabilities because it fails to sufficiently sanitize user-supplied data before using it in an
  SQL query.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Family Connections 2.2.3 is vulnerable, other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.2.3")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"2.0.0 - 2.2.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

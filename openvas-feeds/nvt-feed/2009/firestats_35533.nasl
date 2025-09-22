# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:firestats:firestat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100230");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-08 19:01:22 +0200 (Wed, 08 Jul 2009)");
  script_cve_id("CVE-2009-2144");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FireStats Unspecified SQL Injection Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("firestats_detect.nasl");
  script_mandatory_keys("firestats/installed");

  script_tag(name:"solution", value:"The vendor has released an update.");

  script_tag(name:"summary", value:"FireStats is prone to an SQL-injection vulnerability because it fails to
  sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Versions prior to FireStats 1.6.2 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35533");

  script_xref(name:"URL", value:"http://firestats.cc/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.6.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.6.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
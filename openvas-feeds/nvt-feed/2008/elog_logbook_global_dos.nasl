# SPDX-FileCopyrightText: 2008 Justin Seitz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:stefan_ritt:elog_web_logbook";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80056");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2006-6318");
  script_xref(name:"OSVDB", value:"30272");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ELOG < 2.6.2-7 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Justin Seitz");
  script_family("Denial of Service");
  script_dependencies("secpod_elog_detect.nasl");
  script_mandatory_keys("ELOG/detected");

  script_tag(name:"summary", value:"The version of ELOG Web Logbook installed on the remote host is vulnerable
  to a denial of service attack by requesting '/global' or any logbook with 'global' in its name.");

  script_tag(name:"impact", value:"When a request like described is received, a NULL pointer dereference occurs,
  leading to a crash of the service.");

  script_tag(name:"solution", value:"Update ELOG to version 2.6.2-7 or later.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-11/0198.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21028");
  script_xref(name:"URL", value:"http://savannah.psi.ch/websvn/log.php?repname=elog&path=/trunk/&rev=1749&sc=1&isdir=1");
  script_xref(name:"URL", value:"http://midas.psi.ch/elogs/Forum/2053");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.6.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

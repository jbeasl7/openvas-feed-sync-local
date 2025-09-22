# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:gowondesigns:leap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101026");
  script_version("2023-08-01T13:29:10+0000");
  script_cve_id("CVE-2009-1613", "CVE-2009-1614", "CVE-2009-1615");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-04-30 23:55:19 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Leap CMS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Web application abuses");
  script_dependencies("remote-detect-Leap_CMS.nasl");
  script_mandatory_keys("gowondesigns/leapcms/detected");

  script_tag(name:"solution", value:"For the sql injection vulnerability, set
  your php configuration to magic_quotes_gpc = off, for other vulnerabilities,
  it's recommended to download the latest stable version.");

  script_tag(name:"summary", value:"The remote Leap CMS is affected by multiple
  remote vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if(revcomp(a:vers, b:"0.1.4") <= 0) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See solution tag", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

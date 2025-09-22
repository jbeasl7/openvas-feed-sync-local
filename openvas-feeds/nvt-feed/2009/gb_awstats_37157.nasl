# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:awstats:awstats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100380");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-12-08 22:02:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("AWStats < 6.95 Multiple Unspecified Security Vulnerabilities");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121193209/http://www.securityfocus.com/bid/37157");
  script_xref(name:"URL", value:"http://awstats.sourceforge.net/docs/awstats_changelog.txt");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"qod_type", value:"remote_banner");

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_awstats_http_detect.nasl");
  script_mandatory_keys("awstats/detected");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"AWStats is prone to multiple security vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "6.95")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "6.95");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

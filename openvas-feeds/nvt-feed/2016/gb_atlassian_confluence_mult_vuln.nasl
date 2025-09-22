# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:confluence";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106113");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-04 12:33:39 +0700 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:58:00 +0000 (Tue, 09 Oct 2018)");

  script_cve_id("CVE-2015-8398", "CVE-2015-8399");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Confluence Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_confluence_http_detect.nasl");
  script_mandatory_keys("atlassian/confluence/detected");

  script_tag(name:"summary", value:"Atlassian Confluence is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Atlassian Confluence is prone to two vulnerabilities:

  Cross-site scripting (XSS) vulnerability allows remote attackers to inject arbitrary web script or HTML
  via the PATH_INFO to rest/prototype/1/session/check. (CVE-2015-8398)

  Remote authenticated users may read configuration files via the decoratorName parameter to
  spaces/viewdefaultdecorator.action or admin/viewdefaultdecorator.action. (CVE-2015-8399)");

  script_tag(name:"impact", value:"Unauthenticated remote attackers may inject arbitrary scripts.
  Authenticated attackers may read configuration files.");

  script_tag(name:"affected", value:"Version 5.8.16 and previous.");

  script_tag(name:"solution", value:"Update to 5.8.17 or later versions.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Jan/9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.8.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.17");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

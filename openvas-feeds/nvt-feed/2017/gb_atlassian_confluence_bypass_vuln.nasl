# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:confluence";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106869");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-14 09:24:05 +0700 (Wed, 14 Jun 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-21 16:50:00 +0000 (Tue, 21 Jul 2020)");

  script_cve_id("CVE-2017-9505");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Confluence Access Restriction Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_confluence_http_detect.nasl");
  script_mandatory_keys("atlassian/confluence/detected");

  script_tag(name:"summary", value:"Atlassian Confluence is prone to an access restriction bypass vulnerability
  using watch notifications.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Confluence does not check if a user had permission to view a page when
  creating a workbox notification about new comments. An attacker who can login to Confluence could receive workbox
  notifications, which contain the content of comments, for comments added to a page after they started watching it
  even if they do not have permission to view the page itself.");

  script_tag(name:"affected", value:"Atlassian Confluence 4.3.0 up to 6.1.1.");

  script_tag(name:"solution", value:"Update to 6.2.1 or later versions.");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CONFSERVER-52560");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "6.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

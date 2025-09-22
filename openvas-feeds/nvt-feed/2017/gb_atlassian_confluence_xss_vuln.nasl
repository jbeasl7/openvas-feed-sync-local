# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:confluence";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106492");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-05 11:09:21 +0700 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-20 13:58:00 +0000 (Fri, 20 Jan 2017)");

  script_cve_id("CVE-2016-6283", "CVE-2016-4317");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Confluence XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_confluence_http_detect.nasl");
  script_mandatory_keys("atlassian/confluence/detected");

  script_tag(name:"summary", value:"Atlassian Confluence is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Atlassian Confluence is vulnerable to a persistent cross-site scripting
  vulnerability because it fails to securely validate user controlled data. The bug occurs at pages carrying attached
  files, even though the attached file name parameter is correctly sanitized upon submission, it is possible for an
  attacker to later edit the attached file name property and supply crafted data (i.e HTML tags and script code)
  without the occurrence of any security checks, resulting in an exploitable persistent XSS.");

  script_tag(name:"affected", value:"Atlassian Confluence before version 5.10.6.");

  script_tag(name:"solution", value:"Update to 5.10.6 or later versions.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40989/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.10.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

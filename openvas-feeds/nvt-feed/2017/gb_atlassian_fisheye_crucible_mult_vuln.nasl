# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:fisheye";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140327");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-25 16:27:22 +0700 (Fri, 25 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-25 14:15:00 +0000 (Wed, 25 Nov 2020)");

  script_cve_id("CVE-2017-9507", "CVE-2017-9508", "CVE-2017-9509", "CVE-2017-9510", "CVE-2017-9511",
"CVE-2017-9512");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian FishEye and Crucible Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_fisheye_crucible_detect.nasl");
  script_mandatory_keys("atlassian_fisheye_crucible/installed");

  script_tag(name:"summary", value:"Atlassian FishEye and Crucible is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Atlassian FishEye and Crucible is prone to multiple vulnerabilities:

  - The review dashboard resource in Atlassian Crucible allows remote attackers to inject arbitrary HTML or
JavaScript via a cross site scripting (XSS) vulnerability in the review filter title parameter. (CVE-2017-9507)

  - Various resources in Atlassian FishEye and Crucible allow remote attackers to inject arbitrary HTML or
JavaScript via a cross site scripting (XSS) vulnerability through the name of a repository or review file.
(CVE-2017-9508)

  - The review file upload resource in Atlassian Crucible allows remote attackers to inject arbitrary HTML or
JavaScript via a cross site scripting (XSS) vulnerability through the charset of a previously uploaded file.
(CVE-2017-9509)

  - The repository changelog resource in Atlassian FishEye allows remote attackers to inject arbitrary HTML or
JavaScript via a cross site scripting (XSS) vulnerability through the start date and end date parameters.
(CVE-2017-9510)

  - The MultiPathResource class in Atlassian FishEye and Crucible allows anonymous remote attackers to read
arbitrary files via a path traversal vulnerability when FishEye or Crucible is running on the Microsoft Windows
operating system. (CVE-2017-9511)

  - The mostActiveCommitters.do resource in Atlassian FishEye and Crucible allows anonymous remote attackers to
access sensitive information, for example email addresses of committers, as it lacked permission checks.
(CVE-2017-9512)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 4.4.1 or later.");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CRUC-8043");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CRUC-8044");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/FE-6898");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CRUC-8046");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/FE-6890");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CRUC-8049");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/FE-6891");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CRUC-8053");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/FE-6892");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

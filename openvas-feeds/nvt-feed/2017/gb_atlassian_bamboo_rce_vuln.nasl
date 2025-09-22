# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:bamboo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106878");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-06-16 14:35:00 +0700 (Fri, 16 Jun 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-8907");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Bamboo RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_bamboo_detect.nasl");
  script_mandatory_keys("AtlassianBamboo/Installed");

  script_tag(name:"summary", value:"Atlassian Bamboo is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Bamboo does not correctly check if a user creating a deployment project had
the edit permission and therefore the rights to do so. An attacker who can login to Bamboo as a user without the
edit permission for deployment projects is able to use this vulnerability, provided there is an existing plan
with a green build, to create a deployment project and execute arbitrary code on an available Bamboo Agent. By
default a local agent is enabled this means that code execution can occur on the system hosting Bamboo as the user
running Bamboo.");

  script_tag(name:"affected", value:"Atlassiona Bamboo version 5.0.0 before 5.15.7 and 6.0.0.");

  script_tag(name:"solution", value:"Update to 5.15.7, 6.0.1 or later.");

  script_xref(name:"URL", value:"https://confluence.atlassian.com/bamboo/bamboo-security-advisory-2017-06-14-907283498.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.15.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.15.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version == "6.0.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

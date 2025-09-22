# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:theforeman:foreman";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107147");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-04-11 07:35:49 +0200 (Tue, 11 Apr 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-2672", "CVE-2017-7535");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Foreman CVE-2017-2672 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_foreman_http_detect.nasl");
  script_mandatory_keys("foreman/detected");

  script_tag(name:"summary", value:"Foreman is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When images for compute resources (e.g. an OpenStack image)
  are added/registered in Foreman, the password used to log in is recorded in plain text in the
  audit log. This may allow users with access to view the audit log to access newly provisioned
  hosts using the stored credentials.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  gain access to sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"Foreman version 1.4 through 1.15.4.");

  script_tag(name:"solution", value:"Update to version 1.16.0 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97526");

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

if (version_in_range(version: version, test_version: "1.4", test_version2: "1.15.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.16.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

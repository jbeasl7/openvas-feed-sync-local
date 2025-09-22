# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809433");
  script_version("2023-10-06T16:09:51+0000");
  script_cve_id("CVE-2016-7571", "CVE-2016-7572", "CVE-2016-7570");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-04 17:54:00 +0000 (Tue, 04 Oct 2016)");
  script_tag(name:"creation_date", value:"2016-10-07 10:50:13 +0530 (Fri, 07 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Multiple Vulnerabilities (SA-CORE-2016-004) - Linux");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - The system.temporary route not properly check for 'Export configuration'
    permission.

  - Users without 'Administer comments' set comment visibility on nodes.

  - Cross-site Scripting in http exceptions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to set the visibility of comments for arbitrary nodes
  or to bypass intended access restrictions and read a full config export
  or to inject arbitrary web script.");

  script_tag(name:"affected", value:"Drupal core 8.x versions prior to 8.1.10");

  script_tag(name:"solution", value:"Update to version 8.1.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93101");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"8.0", test_version2:"8.1.9")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.1.10", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:centreon:centreon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811735");
  script_version("2025-01-31T05:37:27+0000");
  script_cve_id("CVE-2015-7672");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-30 19:15:00 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"creation_date", value:"2017-09-11 13:47:50 +0530 (Mon, 11 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Centreon 'Comments' POST Parameter Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Centreon is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient
  sanitization of input passed via 'Comments' POST parameter to main.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary scripts in the logged-in user's web browser.");

  script_tag(name:"affected", value:"Centreon version 2.x up to 2.8.26.");

  script_tag(name:"solution", value:"Upgrade to version 2.8.27, 18.10.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://documentation.centreon.com/docs/centreon/en/latest/release_notes/centreon-2.8/centreon-2.8.27.html");
  script_xref(name:"URL", value:"https://documentation.centreon.com/docs/centreon/en/latest/release_notes/centreon-18.10/centreon-18.10.0.html");
  script_xref(name:"URL", value:"https://github.com/centreon/centreon/pull/6953");
  script_xref(name:"URL", value:"https://www.youtube.com/watch?v=sIONzwQAngU");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_centreon_web_http_detect.nasl");
  script_mandatory_keys("centreon_web/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.8.26")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.8.27/18.10.0");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

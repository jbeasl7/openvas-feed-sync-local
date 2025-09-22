# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811831");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2015-2750", "CVE-2015-2749", "CVE-2015-2559");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-20 19:15:00 +0000 (Wed, 20 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-19 14:05:10 +0530 (Tue, 19 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Core Multiple Vulnerabilities (SA-CORE-2015-001) - Linux");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper validation for 'destination' query string parameter in URLs to
    redirect users to a new destination after completing an action on the current
    page.

  - An improper implementation of several URL-related API functions.

  - An improper handling of Password reset URLs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to another user's account without knowing the
  account's password and also trick users into being redirected to a 3rd party
  website, thereby exposing the users to potential social engineering attacks.");

  script_tag(name:"affected", value:"Drupal core 6.x versions prior to 6.35 and
 7.x versions prior to 7.35 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Drupal core version 6.35 or
  7.35 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2015-001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73219");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73403");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73219");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version =~ "^6\." && version_is_less(version:version, test_version:"6.35")){
  fix = "6.35";
}

else if(version =~ "^7\." && version_is_less(version:version, test_version:"7.35")){
  fix = "7.35";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
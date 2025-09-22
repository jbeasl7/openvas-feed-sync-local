# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813325");
  script_version("2025-02-25T13:24:30+0000");
  script_cve_id("CVE-2017-0936");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-05-02 19:06:32 +0530 (Wed, 02 May 2018)");
  script_name("Nextcloud Server Authorization Bypass Vulnerability (May 2018) - Linux");

  script_tag(name:"summary", value:"Nextcloud Server is prone to authorization bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a missing ownership
  check while changing the scope of app passwords of other users.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to change the scope of app passwords of other users. Note that the app passwords
  themselves where neither disclosed nor could the error be misused to identify as
  another user.");

  script_tag(name:"affected", value:"Nextcloud Server before 11.0.7 and 12.0.5.");

  script_tag(name:"solution", value:"Upgrade to version 11.0.7 or 12.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=nc-sa-2018-001");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/server/detected", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"11.0.7")) {
  fix = "11.0.7";
}

else if(version_in_range(version:vers, test_version:"12.0", test_version2:"12.0.4")) {
  fix = "12.0.5";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

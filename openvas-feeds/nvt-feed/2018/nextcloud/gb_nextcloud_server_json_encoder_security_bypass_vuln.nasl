# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813917");
  script_version("2025-02-25T13:24:30+0000");
  script_cve_id("CVE-2018-3776");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 17:56:00 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2018-08-20 17:29:50 +0530 (Mon, 20 Aug 2018)");
  script_name("Nextcloud Server 'JSON Encoder' Security Bypass Vulnerability");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper validation
  of data passed to JSON encoder.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to not have their actions logged to the audit log.");

  script_tag(name:"affected", value:"Nextcloud Server before 12.0.3 and 11.0.5.");

  script_tag(name:"solution", value:"Upgrade to Nextcloud Server version 11.0.5
  or 12.0.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2018-006");

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

if(version_is_less(version:vers, test_version:"11.0.5")) {
  fix = "11.0.5";
}

else if(version_in_range(version:vers, test_version:"12.0", test_version2:"12.0.2")) {
  fix = "12.0.3";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

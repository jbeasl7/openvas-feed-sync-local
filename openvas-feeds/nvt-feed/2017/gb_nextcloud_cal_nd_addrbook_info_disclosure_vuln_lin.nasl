# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811135");
  script_version("2025-02-25T13:24:30+0000");
  script_cve_id("CVE-2017-0895");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-30 17:45:47 +0530 (Tue, 30 May 2017)");
  script_name("Nextcloud 'Calender and Addressbook' Information Disclosure Vulnerability - Linux");

  script_tag(name:"summary", value:"Nextcloud is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  logical error.");

  script_tag(name:"impact", value:"Successful exploitation will disclose the
  calendar and addressbook names to other logged-in users.");

  script_tag(name:"affected", value:"Nextcloud Server before 10.0.4 and 11.0.2
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Nextcloud Server 10.0.4, or
  11.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=nc-sa-2017-012");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98432");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/server/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^(9|10)\." && version_is_less(version:vers, test_version:"10.0.4")) {
  fix = "10.0.4";
}

else if(vers =~ "^11\." && version_is_less(version:vers, test_version:"11.0.2")) {
  fix = "11.0.2";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

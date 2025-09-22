# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809291");
  script_version("2025-09-04T05:39:49+0000");
  script_cve_id("CVE-2015-5953");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-09-23 15:00:37 +0530 (Fri, 23 Sep 2016)");
  script_name("ownCloud Stored XSS Vulnerability (oC-SA-2015-010) - Linux");

  script_tag(name:"summary", value:"ownCloud is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because the activity application does not
  sanitising all user provided input correctly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to
  inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"ownCloud Server before 7.0.5 and 8.0.x before 8.0.4.");

  script_tag(name:"solution", value:"Update to version 7.0.5, 8.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-010");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^[78]\.") {

  if(version_is_less(version:vers, test_version:"7.0.5")) {
    fix = "7.0.5";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"8.0.0", test_version2:"8.0.3")) {
    fix = "8.0.4";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

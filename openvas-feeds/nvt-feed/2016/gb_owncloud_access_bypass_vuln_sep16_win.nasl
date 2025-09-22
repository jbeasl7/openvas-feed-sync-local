# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809295");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-5954");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-09-23 15:52:23 +0530 (Fri, 23 Sep 2016)");
  script_name("ownCloud Access Bypass Vulnerability (Sep 2016) - Windows");

  script_tag(name:"summary", value:"ownCloud is prone to an access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the virtual
  filesystem does not consider that NULL is a valid getPath return value.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to bypass intended access restrictions and gain access to
  users files.");

  script_tag(name:"affected", value:"ownCloud Server before 6.0.9, 7.0.x
  before 7.0.7, and 8.0.x before 8.0.5 on Windows.");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 6.0.9 or
  7.0.7 or 8.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-011");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^[6-8]") {

  if(version_is_less(version:version, test_version:"6.0.9")) {
    fix = "6.0.9";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"7.0.0", test_version2:"7.0.6")) {
    fix = "7.0.7";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"8.0.0", test_version2:"8.0.4")) {
    fix = "8.0.5";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807403");
  script_version("2024-02-28T05:05:37+0000");
  script_cve_id("CVE-2016-1499");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-03-02 15:04:46 +0530 (Wed, 02 Mar 2016)");
  script_name("ownCloud Information Exposure Vulnerability (Feb 2016) - Linux");

  script_tag(name:"summary", value:"ownCloud is prone to Information Exposure Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an
  incorrect usage of an ownCloud internal file system function.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  remote authenticated users to obtain sensitive information from a directory
  listing and possibly cause a denial of service.");

  script_tag(name:"affected", value:"ownCloud Server 8.2.x before 8.2.2, 8.1.x
  before 8.1.5 and 8.0.x before 8.0.10 on Linux.");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 8.2.2 or 8.1.5
  or 8.0.10 later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2016-002");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79905");

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

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^8") {

  if(version_in_range(version:version, test_version:"8.2.0", test_version2:"8.2.1")) {
    fix = "8.2.2";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"8.1.0", test_version2:"8.1.4")) {
    fix = "8.1.5";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"8.0.0", test_version2:"8.0.9")) {
    fix = "8.0.10";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

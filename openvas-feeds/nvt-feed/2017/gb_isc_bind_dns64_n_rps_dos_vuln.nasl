# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810547");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-3135");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-02-27 13:12:12 +0530 (Mon, 27 Feb 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND DNS64 and RPZ Denial of Service Vulnerability");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to using both DNS64
  and RPZ to rewrite query responses, query processing can resume in an
  inconsistent state.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause an INSIST assertion failure (and subsequent abort) or an
  attempt to read through a NULL pointer.  On most platforms a NULL pointer
  read leads to a segmentation fault (SEGFAULT), which causes the process to
  be terminated.");

  script_tag(name:"affected", value:"ISC BIND versions 9.8.8, 9.9.3-S1 through 9.9.9-S7,
  9.9.3 through 9.9.9-P5, 9.9.10b1, 9.10.0 through 9.10.4-P5, 9.10.5b1, 9.11.0
  through 9.11.0-P2 and 9.11.1b1.");

  script_tag(name:"solution", value:"Update to ISC BIND version 9.9.9-P6 or
  9.10.4-P6 or 9.11.0-P3 or 9.9.9-S8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01453");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96150");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if(version =~ "^9\.") {
  if(version =~ "^9\.9\.[3-9]s[1-7]") {
    fix = "9.9.9-S8";
    VULN = TRUE;
  }

  else if(version =~ "^9\.9\.[3-9]") {
    if(revcomp(a: version, b: "9.9.9p6") < 0) {
      fix = "9.9.9-P6";
      VULN = TRUE;
    }
  }
  else if(version =~ "^9\.10\.") {
    if(revcomp(a: version, b: "9.10.4p6") < 0) {
      fix = "9.10.4-P6";
      VULN = TRUE;
    }
  }
  else if(version =~ "^9\.11\.0") {
    if(revcomp(a: version, b: "9.11.0p3") < 0) {
      fix = "9.11.0-P3";
      VULN = TRUE;
    }
  }
  else if(version_is_equal(version:version, test_version:"9.11.1b1") ||
          version_is_equal(version:version, test_version:"9.10.5b1") ||
          version_is_equal(version:version, test_version:"9.8.8")) {
    fix = "9.11.0-P3 or 9.10.4-P6 or 9.9.9-P6 or 9.9.9-S8";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(data:report, port:port, proto:proto);
  exit(0);
}

exit(99);

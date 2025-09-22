# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810291");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2016-9778");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-01-16 16:59:09 +0530 (Mon, 16 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ISC BIND 'nxdomain-redirect' Feature Response DoS Vulnerability - Windows");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in handling
  certain queries when a server is using the nxdomain-redirect feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure and daemon exit) via
  crafted data.");

  script_tag(name:"affected", value:"ISC BIND 9.9.8-S1 through 9.9.8-S3,
  9.9.9-S1 through 9.9.9-S6 and 9.11.0 through 9.11.0-P1.");

  script_tag(name:"solution", value:"Update to ISC BIND version 9.11.0-P2 or
  9.9.9-S7 later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01441");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95388");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if(version =~ "^9\.") {
  if(version =~ "^9\.9\.9s[1-6]" || version =~ "^9\.9\.8s[1-3]") {
    fix = "9.9.9-S7";
    VULN = TRUE;
  }

  else if(version =~ "^9\.11\.0") {
    if(version_is_less(version:version, test_version: "9.11.0p2")) {
      fix = "9.11.0-P2";
      VULN = TRUE;
    }
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(data:report, port:port, proto:proto);
  exit(0);
}

exit(99);

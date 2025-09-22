# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rancher:rancher";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107248");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2017-7297");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-10-16 10:53:43 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-30 17:25:00 +0000 (Fri, 30 Apr 2021)");
  script_name("Rancher Server Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rancher_detect.nasl");
  script_mandatory_keys("rancher/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97180");
  script_xref(name:"URL", value:"https://github.com/rancher/rancher/issues/8296");

  script_tag(name:"summary", value:"Rancher Server is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Security Exposure: Any authenticated users can disable auth via API.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security restrictions to perform unauthorized actions.");

  script_tag(name:"affected", value:"Rancher Server 1.5.2, 1.4.2, 1.3.4 and 1.2.3. Other versions might be affected as well.");

  script_tag(name:"solution", value:"Update to Rancher Server 1.5.3, 1.4.3, 1.3.5, 1.2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if(vers =~ "^1\.5\." && version_is_less(version: vers, test_version: "1.5.3")) {
  VULN = TRUE;
  fix = "1.5.3";
}

else if(vers =~ "^1\.4\." && version_is_less(version: vers, test_version: "1.4.3")) {
  VULN = TRUE;
  fix = "1.4.3";
}

else if(vers =~ "^1\.3\." && version_is_less(version: vers, test_version: "1.3.5")) {
  VULN = TRUE;
  fix = "1.3.5";
}

else if(vers =~ "^1\.2\." && version_is_less(version: vers, test_version: "1.2.4")) {
  VULN = TRUE;
  fix = "1.2.4";
}

if(VULN) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

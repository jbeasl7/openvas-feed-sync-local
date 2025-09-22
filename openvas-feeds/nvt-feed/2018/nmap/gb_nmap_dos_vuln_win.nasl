# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nmap:nmap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813825");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2018-15173");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-27 11:15:00 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-08-14 12:02:26 +0530 (Tue, 14 Aug 2018)");

  script_name("Nmap Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"Nmap is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to -sV option usage and
  an improper validation for a crafted TCP-based service via an unknown function
  of the component TCP Connection Handler.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause stack consumption leading to denial of service condition.");

  script_tag(name:"affected", value:"Nmap versions 7.70 and prior on Windows.");

  script_tag(name:"solution", value:"Update to Nmap 7.80 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://code610.blogspot.com/2018/07/crashing-nmap-770.html");
  script_xref(name:"URL", value:"https://seclists.org/nmap-announce/2019/0");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_nmap_detect_win.nasl");
  script_mandatory_keys("Nmap/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.80")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.80", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

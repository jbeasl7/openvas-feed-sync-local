# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:portswigger:burp_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813810");
  script_version("2025-01-28T05:37:13+0000");
  script_cve_id("CVE-2018-10377");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-28 05:37:13 +0000 (Tue, 28 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-14 14:26:00 +0000 (Tue, 14 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-08-02 13:11:05 +0530 (Thu, 02 Aug 2018)");
  script_name("Burp Suite < 1.7.34 'Collaborator server certificate' MITM Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Burp Suite Community Edition is prone to a man-in-the-middle
  (MITM) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper validating of Collaborator
  server TLS certificate. It fails to check if the certificate CN matches the hostname, making it
  vulnerable to an active MITM attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow man-in-the-middle attackers to
  obtain interaction data.");

  script_tag(name:"affected", value:"Burp Suite before 1.7.34.");

  script_tag(name:"solution", value:"Update to version 1.7.34 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://releases.portswigger.net/2018/06/1734.html");
  script_xref(name:"URL", value:"https://hackerone.com/reports/337680");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_burp_suite_ce_detect_macosx.nasl");
  script_mandatory_keys("BurpSuite/CE/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"1.7.34")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.7.34", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

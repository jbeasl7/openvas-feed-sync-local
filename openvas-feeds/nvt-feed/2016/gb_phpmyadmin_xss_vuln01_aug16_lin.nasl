# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808254");
  script_version("2024-02-13T05:06:26+0000");
  script_cve_id("CVE-2016-5099");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-13 05:06:26 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-08-04 13:01:28 +0530 (Thu, 04 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("phpMyAdmin Double URL Decoding XSS Vulnerability (PMASA-2016-16) - Linux");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation
  of user supplied inputs that are mishandled during double URL decoding.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via special characters.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.4.x before 4.4.15.6
  and 4.6.x before 4.6.2 on Linux.");

  script_tag(name:"solution", value:"Update to version 4.4.15.6, 4.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-16");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90877");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^4\.4")
{
  if(version_is_less(version:vers, test_version:"4.4.15.6"))
  {
    fix = "4.4.15.6";
    VULN = TRUE;
  }
}

else if(vers =~ "^4\.6")
{
  if(version_is_less(version:vers, test_version:"4.6.2"))
  {
    fix = "4.6.2";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(port:port, data:report);
  exit(0);
}

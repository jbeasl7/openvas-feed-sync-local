# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:insight_diagnostics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800191");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4111");
  script_name("HP System Management Homepage (SMH) Insight Diagnostics XSS Vulnerability (HPSBMA02615) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_insight_diag_ssh_login_detect.nasl");
  script_mandatory_keys("hp/smh/insight_diagnostics/ssh-login/detected");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=129245189832672&w=2");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Dec/1024897.html");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-c02652463");

  script_tag(name:"summary", value:"HP System Management Homepage (SMH) with Insight Diagnostics is
  prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused due imporper validation of user supplied
  input via unspecified vectors, which allows attackers to execute arbitrary HTML and script code in
  a user's browser session in the context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary
  HTML code in the context of an affected site.");

  script_tag(name:"affected", value:"HP Insight Diagnostics Online Edition versions prior to
  8.5.1.3712.");

  script_tag(name:"solution", value:"Update to version 8.5.1.3712 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"8.5.1.3712")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.5.1.3712", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

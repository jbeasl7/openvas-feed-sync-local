# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117445");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-05-20 06:20:13 +0000 (Thu, 20 May 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-22 18:04:00 +0000 (Tue, 22 Jun 2021)");

  script_cve_id("CVE-2021-22885", "CVE-2021-22902", "CVE-2021-22903", "CVE-2021-22904");

  script_name("Discourse 2.7.0.beta9 Security Update");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"A new Discourse update includes one security fix.");

  script_tag(name:"insight", value:"Rails was updated to version 6.1.3.2 fixing the following flaws:

  - CVE-2021-22902: Possible Denial of Service vulnerability in Action Dispatch

  - CVE-2021-22903: Possible Open Redirect Vulnerability in Action Pack

  - CVE-2021-22885: Possible Information Disclosure / Unintended Method Execution in Action Pack

  - CVE-2021-22904: Possible DoS Vulnerability in Action Controller Token Authentication");

  script_tag(name:"affected", value:"Discourse up to and including version 2.7.0.beta8.");

  script_tag(name:"solution", value:"Update to version 2.7.0.beta9 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://meta.discourse.org/t/2-7-0-beta9-messages-with-invites-blank-page-education-text-like-webhooks-and-more/189944");
  script_xref(name:"URL", value:"https://weblog.rubyonrails.org/2021/5/5/Rails-versions-6-1-3-2-6-0-3-7-5-2-4-6-and-5-2-6-have-been-released/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];

if( version_is_less( version:vers, test_version:"2.7.0" ) ||
    version_in_range( version:vers, test_version:"2.7.0.beta1", test_version2:"2.7.0.beta8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.7.0.beta9", install_path:infos["location"] );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

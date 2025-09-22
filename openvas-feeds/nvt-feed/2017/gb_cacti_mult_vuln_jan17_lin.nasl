# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108297");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-11-23 13:54:25 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-29 18:00:00 +0000 (Wed, 29 Nov 2017)");

  script_cve_id("CVE-2014-4000", "CVE-2016-10700");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti < 1.0.0 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cacti_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-4000: PHP object injection attack and code execution via a crafted serialized object,
  related to calling unserialize(stripslashes()) ().

  - CVE-2016-10700: auth_login.php allows remote authenticated users who use web authentication
  to bypass intended access restrictions by logging in as a user not in the cacti database,
  because the guest user is not considered.
  NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-2313.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Cacti versions prior to 1.0.0.");

  script_tag(name:"solution", value:"Update to version 1.0.0 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20170208152238/http://www.cacti.net/release_notes_1_0_0.php");
  script_xref(name:"URL", value:"https://web.archive.org/web/20160817090458/http://bugs.cacti.net/view.php?id=2697");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

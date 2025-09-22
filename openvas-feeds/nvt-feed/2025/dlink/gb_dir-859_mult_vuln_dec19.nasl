# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-859_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134003");
  script_version("2025-06-27T05:41:33+0000");
  script_tag(name:"last_modification", value:"2025-06-27 05:41:33 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-05-16 14:12:56 +0000 (Fri, 16 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-08 19:47:05 +0000 (Wed, 08 Jan 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-17621", "CVE-2019-20213", "CVE-2019-20215", "CVE-2019-20216",
                "CVE-2019-20217");

  script_name("D-Link DIR-859 < 1.07b03_beta Multiple Vulnerabilities (SAP10146, SAP10147)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-859 devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-17621: The UPnP endpoint URL /gena.cgi allows an unauthenticated remote attacker to
  execute system commands as root, by sending a specially crafted HTTP SUBSCRIBE request to the UPnP
  service when connecting to the local network.

  - CVE-2019-20213: An information disclosure vulnerability

  - CVE-2019-20215, CVE-2019-20216, CVE-2019-20217: Remote code execution (RCE) via UPnP ssdpcfgi()
  LAN-side vulnerabilities");

  script_tag(name:"affected", value:"D-Link DIR-859 firmware versions prior to 1.07b03_beta.");

  script_tag(name:"solution", value:"Update to firmware version 1.07b03_beta or later.

  Note: You must update your router twice to close this security issue. See vendor advisory for
  further information.

  Note2: Vendor states that DIR-859 reached its End-of-Support Date in 10.12.2020, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10146");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10147");
  script_xref(name:"URL", value:"https://medium.com/@s1kr10s/d-link-dir-859-unauthenticated-information-disclosure-en-faf1a9a13f3f");
  script_xref(name:"URL", value:"https://medium.com/@s1kr10s/d-link-dir-859-unauthenticated-rce-in-ssdpcgi-http-st-cve-2019-20215-en-2e799acb8a73");
  script_xref(name:"URL", value:"https://medium.com/@s1kr10s/d-link-dir-859-rce-unauthenticated-cve-2019-20216-cve-2019-20217-en-6bca043500ae");
  script_xref(name:"URL", value:"https://medium.com/@s1kr10s/d-link-dir-859-rce-unautenticated-cve-2019-17621-en-d94b47a15104");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=sap10267");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if( revcomp( a:version, b:"1.07b03" ) < 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.07b03_beta" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

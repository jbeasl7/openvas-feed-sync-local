# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redhat:openshift";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126043");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-06-17 08:30:33 +0000 (Fri, 17 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 13:31:00 +0000 (Mon, 18 Apr 2022)");

  script_cve_id("CVE-2021-4047");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Red Hat OpenShift 4.9 < 4.9.11 haproxy Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_redhat_openshift_http_detect.nasl");
  script_mandatory_keys("redhat/openshift/detected");

  script_tag(name:"summary", value:"Red Hat OpenShift is prone to a vulnerability in the haproxy
  package.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The release of OpenShift 4.9.6 included four CVE fixes for the
  haproxy package, however the patch for CVE-2021-39242 was missing.");

  script_tag(name:"affected", value:"Red Hat OpenShift 4.9 prior to 4.9.11.");

  script_tag(name:"solution", value:"Update to version 4.9.11 or later.");

  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2021-4047");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2027881");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_in_range( version:version, test_version:"4.9", test_version2:"4.9.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.9.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

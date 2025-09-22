# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108560");
  script_version("2024-10-25T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-10-25 05:05:38 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"creation_date", value:"2019-03-16 08:57:17 +0100 (Sat, 16 Mar 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Report outdated / end-of-life Scan Engine / Environment (local)");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("global_settings.nasl");
  # Greenbone OS (GOS) installations have their own update notification in the admin shell. In
  # addition the check isn't valid for the Greenbone Cloud Services (GCS) at all.
  # nb: FEED_NAME (in global_settings.nasl) is used because this VT would run / be launched on the
  # GCS otherwise which is something we don't want to do. A different approach is (at least
  # currently) not possible because we don't know from NASL side if we're running on the GCS or on
  # a GOS running on the Enterprise TRIAL/Free.
  # The only drawback of that approach is that a Greenbone Enterprise TRIAL/Free with a TRIAL GSF
  # key is missed but this is currently acceptable due to the restricted time frame of the trial.
  script_exclude_keys("keys/is_gef");

  script_tag(name:"summary", value:"This script checks and reports an outdated or end-of-life scan
  engine for the following environments:

  - Greenbone Community Edition

  - Greenbone Free (formerly Greenbone Enterprise TRIAL, Greenbone Security Manager TRIAL /
  Greenbone Community Edition VM)

  used for this scan.

  NOTE: While this is not, in and of itself, a security vulnerability, a severity is reported to
  make you aware of a possible decreased scan coverage or missing detection of vulnerabilities on
  the target due to e.g.:

  - missing functionalities

  - missing bugfixes

  - incompatibilities within the feed");

  script_tag(name:"solution", value:"Update to the latest available stable release for your scan
  environment.

  Note: It is NOT enough to only update the scanner component. All components should be updated to
  the most recent and stable versions.

  Possible solution options depends on the installation method:

  - If using the Greenbone Free: Please do a new installation with the newest available version

  - If using the official Greenbone Community Containers: Please see the references on how to do an
    update of these

  - If the Greenbone Community Edition was build from sources by following the official source build
    documentation: Please see the references on how to do an update of all components

  - If using packages provided by your Linux distribution: Please contact the maintainer of the used
    distribution / repository and request updated packages

  - If using any other installation method: Please contact the provider of this solution

  Please check the references for more information.

  If you want to accept the risk of a possible decreased scan coverage or missing detection of
  vulnerabilities on the target you can set a global override for this script as described in the
  linked GSM manual.");

  script_xref(name:"URL", value:"https://www.greenbone.net/en/testnow/");
  script_xref(name:"URL", value:"https://www.greenbone.net/en/greenbone-free/");
  script_xref(name:"URL", value:"https://greenbone.github.io/docs/latest/22.4/container/workflows.html#updating-the-greenbone-community-containers");
  script_xref(name:"URL", value:"https://greenbone.github.io/docs/latest/22.4/source-build/workflows.html#updating-to-newer-releases");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/greenbone-community-edition-22-4-stable-initial-release-2022-07-25/12638");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/greenbone-community-edition-21-04-end-of-life/13837");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-21-04-end-of-life-initial-release-2021-04-16/8942");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-20-08-end-of-life-initial-release-2020-08-12/6312");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-11-end-of-life-initial-release-2019-10-14/3674");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-10-end-of-life-initial-release-2019-04-05/208");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-9-end-of-life-initial-release-2017-03-07/211");
  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html#creating-an-override");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

# nb: We also don't want to run if optimize_test is set to "no"
if( get_kb_item( "keys/is_gef" ) )
  exit( 0 );

include("version_func.inc");
include("misc_func.inc");

# nb: Different version scheme (with / without leading 0) is expected.
expected_gb_free_ver = "22.04.24";
# nb: OPENVAS_VERSION returns the version of the scanner since GVM-10
# As of 05/2024 version 23.3.0 is current. But the official docs are currently telling the user to
# install 23.0.1. As 23.0.0 is containing an important fix / update for interrupted scans:
# https://github.com/greenbone/openvas-scanner/pull/1528
# reported at various places only 23.0.1 is included here to reduce "noise" for users as most of the
# recent changes are only about the not-used RUST implementation.
expected_scanner_ver1 = "23.0.1";

if( gos_vers = get_local_gos_version() ) {
  if( version_is_less( version:gos_vers, test_version:expected_gb_free_ver ) ) {
    report  = "Installed Greenbone Free version:        " + gos_vers + '\n';
    report += "Latest available Greenbone Free version: " + expected_gb_free_ver + '\n';
    report += "Reference URL:                      https://www.greenbone.net/en/testnow/";
    security_message( port:0, data:report );
    exit( 0 );
  }
} else if( OPENVAS_VERSION && OPENVAS_VERSION =~ "^[0-9.]+" ) {
  if( version_is_less( version:OPENVAS_VERSION, test_version:expected_scanner_ver1 ) ) {
    report  = "Version of installed component:           " + OPENVAS_VERSION + ' (Installed component: openvas-libraries on OpenVAS <= 9, openvas-scanner on Greenbone Community Edition >= 10)\n';
    report += "Latest available openvas-scanner version: " + expected_scanner_ver1 + ' (Minimum recommended version, there are more recent available)\n';
    report += "Reference URL(s) for the latest available version: https://forum.greenbone.net/t/greenbone-community-edition-22-4-stable-initial-release-2022-07-25/12638";
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

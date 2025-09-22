# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833193");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2018-11759");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-22 18:50:02 +0000 (Fri, 22 Feb 2019)");
  script_tag(name:"creation_date", value:"2024-03-04 08:05:14 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for apache2 (SUSE-SU-2023:4513-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4513-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AHYWEPQVEU2LQ7KZT63RGIDLJWIQZOIV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the SUSE-SU-2023:4513-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2-mod_jk fixes the following issues:

  Update to version 1.2.49: Apache * Retrieve default request id from
  mod_unique_id. It can also be taken from an arbitrary environment variable by
  configuring 'JkRequestIdIndicator'. * Don't delegate the generatation of the
  response body to httpd when the status code represents an error if the request
  used the HEAD method. * Only export the main module symbol. Visibility of module
  internal symbols led to crashes when conflicting with library symbols. Based on
  a patch provided by Josef ejka. * Remove support for implicit mapping of
  requests to workers. All mappings must now be explicit. IIS * Set default
  request id as a GUID. It can also be taken from an arbitrary request header by
  configuring 'request_id_header'. * Fix non-empty check for the Translate header.
  Common * Fix compiler warning when initializing and copying fixed length
  strings. * Add a request id to mod_jk log lines. * Enable configure to find the
  correct sizes for pid_t and pthread_t when building on MacOS. * Fix Clang 15/16
  compatibility. Pull request #6 provided by Sam James. * Improve XSS hardening in
  status worker. * Add additional bounds and error checking when reading AJP
  messages. Docs * Remove support for the Netscape / Sun ONE / Oracle iPlanet Web
  Server as the product has been retired. * Remove links to the old JK2
  documentation. The JK2 documentation is still available, it is just no longer
  linked from the current JK documentation. * Restructure subsections in changelog
  starting with version 1.2.45.

  Changes for 1.2.47 and 1.2.48 updates: * Add: Apache: Extend trace level logging
  of method entry/exit to aid debugging of request mapping issues. * Fix: Apache:
  Fix a bug in the normalization checks that prevented file based requests, such
  as SSI file includes, from being processed. * Fix: Apache: When using
  JkAutoAlias, ensure that files that include spaces in their name are accessible.

  * Update: Common: Update the documentation to reflect that the source code for
  the Apache Tomcat Connectors has moved from Subversion to Git. * Fix: Common:
  When using set_session_cookie, ensure that an updated session cookie is issued
  if the load-balancer has to failover to a different worker. * Update: Common:

  Update to version 1.2.46 Fixes: * Apache: Fix regression in 1.2.44 which
  resulted in socket_connect_timeout to be interpreted in ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'apache2' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_jk-debuginfo", rpm:"apache2-mod_jk-debuginfo~1.2.49~150100.6.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_jk-debugsource", rpm:"apache2-mod_jk-debugsource~1.2.49~150100.6.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_jk", rpm:"apache2-mod_jk~1.2.49~150100.6.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_jk-debuginfo", rpm:"apache2-mod_jk-debuginfo~1.2.49~150100.6.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_jk-debugsource", rpm:"apache2-mod_jk-debugsource~1.2.49~150100.6.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_jk", rpm:"apache2-mod_jk~1.2.49~150100.6.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

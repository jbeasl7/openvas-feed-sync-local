# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833828");
  script_cve_id("CVE-2023-49084", "CVE-2023-49085", "CVE-2023-49086", "CVE-2023-49088", "CVE-2023-50250", "CVE-2023-51448");
  script_tag(name:"creation_date", value:"2024-03-04 12:52:17 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 17:15:09 +0000 (Fri, 22 Dec 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0031-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IZJKJNYP7JFJ3XMRIGZT22J5DIAVPSY7/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218381");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti, cacti-spine' package(s) announced via the openSUSE-SU-2024:0031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cacti, cacti-spine fixes the following issues:

cacti-spine 1.2.26:

* Fix: Errors when uptime OID is not present
* Fix: MySQL reconnect option is depreciated
* Fix: Spine does not check a host with no poller items
* Fix: Poller may report the wrong number of devices polled
* Feature: Allow users to override the threads setting at the command line
* Feature: Allow spine to run in ping-only mode

cacti 1.2.26:

* CVE-2023-50250: XSS vulnerability when importing a template file (boo#1218380)
* CVE-2023-49084: RCE vulnerability when managing links (boo#1218360)
* CVE-2023-49085: SQL Injection vulnerability when managing poller devices (boo#1218378)
* CVE-2023-49086: XSS vulnerability when adding new devices (boo#1218366)
* CVE-2023-49088: XSS vulnerability when viewing data sources in debug mode (boo#1218379)
* CVE-2023-51448: SQL Injection vulnerability when managing SNMP Notification Receivers (boo#1218381)
* When viewing data sources, an undefined variable error may be seen
* Improvements for Poller Last Run Date
* Attempting to edit a Data Query that does not exist throws warnings and not an GUI error
* Improve PHP 8.1 support when adding devices
* Viewing Data Query Cache can cause errors to be logged
* Preserve option is not properly honoured when removing devices at command line
* Infinite recursion is possible during a database failure
* Monitoring Host CPU's does not always work on Windows endpoints
* Multi select drop down list box not rendered correctly in Chrome and Edge
* Selective Plugin Debugging may not always work as intended
* During upgrades, Plugins may be falsely reported as incompatible
* Plugin management at command line does not work with multiple plugins
* Improve PHP 8.1 support for incrementing only numbers
* Allow the renaming of guest and template accounts
* DS Stats issues warnings when the RRDfile has not been initialized
* When upgrading, missing data source profile can cause errors to be logged
* When deleting a single Data Source, purge historical debug data
* Improvements to form element warnings
* Some interface aliases do not appear correctly
* Aggregate graph does not show other percentiles
* Settings table updates for large values reverted by database repair
* When obtaining graph records, error messages may be recorded
* Unable to change a device's community at command line
* Increase timeout for RRDChecker
* When viewing a graph, option to edit template may lead to incorrect URL
* When upgrading, failures may occur due to missing color table keys
* On installation, allow a more appropriate template to be used as the default
* When data input parameters are allowed to be null, allow null
* CSV Exports may not always output data correctly
* When debugging a graph, long CDEF's can cause undesirable scrolling
* Secondary LDAP server not evaluated when the first one has failed
* When adding a device, using the bulk walk ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cacti, cacti-spine' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.2.26~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.26~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
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

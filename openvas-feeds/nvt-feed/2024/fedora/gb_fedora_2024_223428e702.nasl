# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.223428101702");
  script_cve_id("CVE-2023-52424");
  script_tag(name:"creation_date", value:"2024-09-11 04:13:54 +0000 (Wed, 11 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-223428e702)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-223428e702");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-223428e702");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2294016");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307290");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310802");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310805");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez, iwd, libell' package(s) announced via the FEDORA-2024-223428e702 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libell 0.69:

 Add support for getting remaining microseconds left on a timer.
 Add support for setting link MTU on a network interface.

iwd 2.21:

 Fix issue with pending scan requests after regdom update.
 Fix issue with handling the rearming of the roaming timeout.
 Fix issue with survey request and externally triggered scans.
 Fix issue with RSSI fallback when setting CQM threshold fails.
 Fix issue with FT-over-Air without offchannel support.
 Add support for per station Affinities property.

bluez 5.78:

 Fix issue with handling notification of scanned BISes to BASS
 Fix issue with handling checking BIS caps against peer caps.
 Fix issue with handling MGMT Set Device Flags overwrites.
 Fix issue with handling ASE notification order.
 Fix issue with handling BIG Info report events.
 Fix issue with handling PACS Server role.
 Fix issue with registering UHID_START multiple times.
 Fix issue with pairing method not setting auto-connect.");

  script_tag(name:"affected", value:"'bluez, iwd, libell' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-cups", rpm:"bluez-cups~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-cups-debuginfo", rpm:"bluez-cups-debuginfo~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debuginfo", rpm:"bluez-debuginfo~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debugsource", rpm:"bluez-debugsource~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-deprecated", rpm:"bluez-deprecated~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-deprecated-debuginfo", rpm:"bluez-deprecated-debuginfo~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-hid2hci", rpm:"bluez-hid2hci~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-hid2hci-debuginfo", rpm:"bluez-hid2hci-debuginfo~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs", rpm:"bluez-libs~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs-debuginfo", rpm:"bluez-libs-debuginfo~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs-devel", rpm:"bluez-libs-devel~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs-devel-debuginfo", rpm:"bluez-libs-devel-debuginfo~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-mesh", rpm:"bluez-mesh~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-mesh-debuginfo", rpm:"bluez-mesh-debuginfo~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-obexd", rpm:"bluez-obexd~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-obexd-debuginfo", rpm:"bluez-obexd-debuginfo~5.78~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd", rpm:"iwd~2.21~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd-debuginfo", rpm:"iwd-debuginfo~2.21~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd-debugsource", rpm:"iwd-debugsource~2.21~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell", rpm:"libell~0.69~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell-debuginfo", rpm:"libell-debuginfo~0.69~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell-debugsource", rpm:"libell-debugsource~0.69~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell-devel", rpm:"libell-devel~0.69~1.fc40", rls:"FC40"))) {
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

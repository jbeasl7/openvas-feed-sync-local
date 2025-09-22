# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.353479810291020");
  script_cve_id("CVE-2023-44431", "CVE-2023-51580", "CVE-2023-51589", "CVE-2023-51592", "CVE-2023-51594", "CVE-2023-51596");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-08 16:17:35 +0000 (Tue, 08 Jul 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-35347bf9f0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-35347bf9f0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-35347bf9f0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278949");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278957");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278963");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278966");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278968");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278970");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2344813");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez, iwd, libell' package(s) announced via the FEDORA-2025-35347bf9f0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"bluez 5.80:

 Fix issue with handling address type for all types of keys.
 Fix issue with handling maximum number of GATT channels.
 Fix issue with handling MTU auto-tuning feature.
 Fix issue with handling AVRCP volume in reconfigured transports.
 Fix issue with handling VCP volume setting requests.
 Fix issue with handling VCP connection management.
 Fix issue with handling MAP qualification.
 Fix issue with handling PBAP qualification.
 Fix issue with handling BNEP qualification.
 Add support for PreferredBearer device property.
 Add support for SupportedTypes Message Access property.
 Add support for HFP, A2DP, AVRCP, AVCTP and MAP latest versions.

iwd 3.4:

 Add support for the Test Anything Protocol.

libell 0.74:

 Add support for NIST P-192 curve usage with ECDH.
 Add support for SHA-224 based checksums and HMACs.

libell 0.73:

 Fix issue with parsing hwdb.bin child structures.

libell 0.72:

 Add support for the Test Anything Protocol.");

  script_tag(name:"affected", value:"'bluez, iwd, libell' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-cups", rpm:"bluez-cups~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-cups-debuginfo", rpm:"bluez-cups-debuginfo~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debuginfo", rpm:"bluez-debuginfo~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debugsource", rpm:"bluez-debugsource~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-deprecated", rpm:"bluez-deprecated~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-deprecated-debuginfo", rpm:"bluez-deprecated-debuginfo~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-hid2hci", rpm:"bluez-hid2hci~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-hid2hci-debuginfo", rpm:"bluez-hid2hci-debuginfo~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs", rpm:"bluez-libs~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs-debuginfo", rpm:"bluez-libs-debuginfo~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs-devel", rpm:"bluez-libs-devel~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs-devel-debuginfo", rpm:"bluez-libs-devel-debuginfo~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-mesh", rpm:"bluez-mesh~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-mesh-debuginfo", rpm:"bluez-mesh-debuginfo~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-obexd", rpm:"bluez-obexd~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-obexd-debuginfo", rpm:"bluez-obexd-debuginfo~5.80~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd", rpm:"iwd~3.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd-debuginfo", rpm:"iwd-debuginfo~3.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd-debugsource", rpm:"iwd-debugsource~3.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell", rpm:"libell~0.74~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell-debuginfo", rpm:"libell-debuginfo~0.74~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell-debugsource", rpm:"libell-debugsource~0.74~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell-devel", rpm:"libell-devel~0.74~1.fc42", rls:"FC42"))) {
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

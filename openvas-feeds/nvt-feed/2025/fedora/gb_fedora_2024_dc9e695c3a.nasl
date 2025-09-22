# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.10099910169599397");
  script_cve_id("CVE-2023-41913");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 17:07:01 +0000 (Tue, 12 Dec 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-dc9e695c3a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-dc9e695c3a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-dc9e695c3a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250666");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254560");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the FEDORA-2024-dc9e695c3a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for strongswan-5.9.14-1.fc41.

##### **Changelog**

```
* Fri May 31 2024 Paul Wouters <paul.wouters@aiven.io> - 5.9.14-1
- Resolves: rhbz#2254560 CVE-2023-41913 buffer overflow and possible RCE
- Resolved: rhbz#2250666 Update to 5.9.14 (IKEv2 OCSP extensions, seqno/regno overflow handling
- Update to 5.9.13 (OCSP nonce set regression configuration option charon.ocsp_nonce_len)
- Update to 5.9.12 (CVE-2023-41913 fix, various IKEv2 fixes)

```");

  script_tag(name:"affected", value:"'strongswan' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"perl-vici", rpm:"perl-vici~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-vici", rpm:"python3-vici~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-charon-nm", rpm:"strongswan-charon-nm~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-charon-nm-debuginfo", rpm:"strongswan-charon-nm-debuginfo~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debuginfo", rpm:"strongswan-debuginfo~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debugsource", rpm:"strongswan-debugsource~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libipsec", rpm:"strongswan-libipsec~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libipsec-debuginfo", rpm:"strongswan-libipsec-debuginfo~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-sqlite", rpm:"strongswan-sqlite~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-sqlite-debuginfo", rpm:"strongswan-sqlite-debuginfo~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-tnc-imcvs", rpm:"strongswan-tnc-imcvs~5.9.14~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-tnc-imcvs-debuginfo", rpm:"strongswan-tnc-imcvs-debuginfo~5.9.14~1.fc41", rls:"FC41"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.98217771001985");
  script_cve_id("CVE-2024-11029");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-15 13:15:08 +0000 (Wed, 15 Jan 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-b21777d1b5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b21777d1b5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b21777d1b5");
  script_xref(name:"URL", value:"https://www.freeipa.org/release-notes/4-12-3.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeipa' package(s) announced via the FEDORA-2025-b21777d1b5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-11029

Release note: [link moved to references]");

  script_tag(name:"affected", value:"'freeipa' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"freeipa", rpm:"freeipa~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client", rpm:"freeipa-client~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client-common", rpm:"freeipa-client-common~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client-debuginfo", rpm:"freeipa-client-debuginfo~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client-epn", rpm:"freeipa-client-epn~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client-samba", rpm:"freeipa-client-samba~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-common", rpm:"freeipa-common~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-debuginfo", rpm:"freeipa-debuginfo~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-debugsource", rpm:"freeipa-debugsource~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-python-compat", rpm:"freeipa-python-compat~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-selinux", rpm:"freeipa-selinux~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-selinux-luna", rpm:"freeipa-selinux-luna~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-selinux-nfast", rpm:"freeipa-selinux-nfast~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server", rpm:"freeipa-server~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-common", rpm:"freeipa-server-common~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-debuginfo", rpm:"freeipa-server-debuginfo~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-dns", rpm:"freeipa-server-dns~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-trust-ad", rpm:"freeipa-server-trust-ad~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-trust-ad-debuginfo", rpm:"freeipa-server-trust-ad-debuginfo~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipaclient", rpm:"python3-ipaclient~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipalib", rpm:"python3-ipalib~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipaserver", rpm:"python3-ipaserver~4.12.2~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipatests", rpm:"python3-ipatests~4.12.2~7.fc41", rls:"FC41"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3799301710245");
  script_cve_id("CVE-2024-10573");
  script_tag(name:"creation_date", value:"2025-07-21 04:19:44 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-07-21T05:44:15+0000");
  script_tag(name:"last_modification", value:"2025-07-21 05:44:15 +0000 (Mon, 21 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-31 19:15:12 +0000 (Thu, 31 Oct 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2025-37c3017f45)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-37c3017f45");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-37c3017f45");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322991");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357561");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2376125");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wine, wine-mono' package(s) announced via the FEDORA-2025-37c3017f45 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"### wine
- Update to v10.12.
- Drop unneeded libOSMesa dependency.

### wine-mono
- Update to v10.1.0.");

  script_tag(name:"affected", value:"'wine, wine-mono' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"wine", rpm:"wine~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-alsa", rpm:"wine-alsa~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-alsa-debuginfo", rpm:"wine-alsa-debuginfo~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-arial-fonts", rpm:"wine-arial-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-cms", rpm:"wine-cms~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-common", rpm:"wine-common~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-core", rpm:"wine-core~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-core-debuginfo", rpm:"wine-core-debuginfo~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-courier-fonts", rpm:"wine-courier-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-debuginfo", rpm:"wine-debuginfo~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-debugsource", rpm:"wine-debugsource~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-desktop", rpm:"wine-desktop~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-devel", rpm:"wine-devel~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-devel-debuginfo", rpm:"wine-devel-debuginfo~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-filesystem", rpm:"wine-filesystem~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-fixedsys-fonts", rpm:"wine-fixedsys-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-fonts", rpm:"wine-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-ldap", rpm:"wine-ldap~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-marlett-fonts", rpm:"wine-marlett-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-mono", rpm:"wine-mono~10.1.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-ms-sans-serif-fonts", rpm:"wine-ms-sans-serif-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-opencl", rpm:"wine-opencl~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-opencl-debuginfo", rpm:"wine-opencl-debuginfo~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-pulseaudio", rpm:"wine-pulseaudio~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-pulseaudio-debuginfo", rpm:"wine-pulseaudio-debuginfo~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-small-fonts", rpm:"wine-small-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-smartcard", rpm:"wine-smartcard~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-smartcard-debuginfo", rpm:"wine-smartcard-debuginfo~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-symbol-fonts", rpm:"wine-symbol-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-system-fonts", rpm:"wine-system-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-systemd", rpm:"wine-systemd~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-tahoma-fonts", rpm:"wine-tahoma-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-tahoma-fonts-system", rpm:"wine-tahoma-fonts-system~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-times-new-roman-fonts", rpm:"wine-times-new-roman-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-times-new-roman-fonts-system", rpm:"wine-times-new-roman-fonts-system~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-twain", rpm:"wine-twain~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-twain-debuginfo", rpm:"wine-twain-debuginfo~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-webdings-fonts", rpm:"wine-webdings-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-wingdings-fonts", rpm:"wine-wingdings-fonts~10.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wine-wingdings-fonts-system", rpm:"wine-wingdings-fonts-system~10.12~2.fc41", rls:"FC41"))) {
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

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856641");
  script_cve_id("CVE-2024-50382", "CVE-2024-50383");
  script_tag(name:"creation_date", value:"2024-10-31 05:01:43 +0000 (Thu, 31 Oct 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0343-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0343-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JIB3PGKG47QR6R5PTCZJFDYCEELC6BOJ/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232301");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Botan' package(s) announced via the openSUSE-SU-2024:0343-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Botan fixes the following issues:

- Fixed CVE-2024-50382, CVE-2024-50383 - various compiler-induced side channel in GHASH when certain LLVM/GCC versions are used to compile Botan.");

  script_tag(name:"affected", value:"'Botan' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"Botan", rpm:"Botan~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Botan-doc", rpm:"Botan-doc~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19", rpm:"libbotan-2-19~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19-32bit", rpm:"libbotan-2-19-32bit~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19-64bit", rpm:"libbotan-2-19-64bit~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel", rpm:"libbotan-devel~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel-32bit", rpm:"libbotan-devel-32bit~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel-64bit", rpm:"libbotan-devel-64bit~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-botan", rpm:"python3-botan~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"Botan", rpm:"Botan~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Botan-doc", rpm:"Botan-doc~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19", rpm:"libbotan-2-19~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19-32bit", rpm:"libbotan-2-19-32bit~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19-64bit", rpm:"libbotan-2-19-64bit~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel", rpm:"libbotan-devel~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel-32bit", rpm:"libbotan-devel-32bit~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel-64bit", rpm:"libbotan-devel-64bit~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-botan", rpm:"python3-botan~2.19.5~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
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

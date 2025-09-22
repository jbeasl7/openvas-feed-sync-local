# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833335");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2019-13590", "CVE-2021-23159", "CVE-2021-33844", "CVE-2021-3643", "CVE-2021-40426", "CVE-2022-31650", "CVE-2022-31651", "CVE-2023-32627", "CVE-2023-34318", "CVE-2023-34432");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-10 17:00:14 +0000 (Tue, 10 May 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:31:07 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for sox (openSUSE-SU-2023:0329-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0329-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OWH3Y6RJSLCAZ7XAIEM2FMD5E6EQYZM5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sox'
  package(s) announced via the openSUSE-SU-2023:0329-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sox fixes the following issues:

  - Apply various fix patches taken from Debian package  it fixes also other
       entries (CVE-2022-31650 boo#1212060 CVE-2023-34318 boo#1212062
       CVE-2023-34432 boo#1212063)

  - Fix floating point exception in src/voc.c (CVE-2023-32627 boo#1212061)");

  script_tag(name:"affected", value:"'sox' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libsox3", rpm:"libsox3~14.4.2~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sox", rpm:"sox~14.4.2~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sox-devel", rpm:"sox-devel~14.4.2~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsox3", rpm:"libsox3~14.4.2~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sox", rpm:"sox~14.4.2~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sox-devel", rpm:"sox-devel~14.4.2~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
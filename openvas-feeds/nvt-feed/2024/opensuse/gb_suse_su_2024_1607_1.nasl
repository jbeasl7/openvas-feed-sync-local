# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856135");
  script_cve_id("CVE-2021-25287", "CVE-2021-25288", "CVE-2021-28675", "CVE-2021-28676", "CVE-2021-28677", "CVE-2021-28678");
  script_tag(name:"creation_date", value:"2024-05-13 01:00:51 +0000 (Mon, 13 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-08 16:33:17 +0000 (Tue, 08 Jun 2021)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1607-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1607-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241607-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185805");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035237.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Pillow' package(s) announced via the SUSE-SU-2024:1607-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Pillow fixes the following issues:

- CVE-2021-25287: out-of-bounds read in J2kDecode in j2ku_graya_la (bsc#1185805)
- CVE-2021-25288: out-of-bounds read in J2kDecode in j2ku_gray_i (bsc#1185803)
- CVE-2021-28675: DoS in PsdImagePlugin (bsc#1185804)
- CVE-2021-28676: infinite loop in FliDecode.c can lead to DoS (bsc#1185786)
- CVE-2021-28677: DoS in the open phase via a malicious EPS file (bsc#1185785)
- CVE-2021-28678: improper check in BlpImagePlugin can lead to DoS (bsc#1185784)");

  script_tag(name:"affected", value:"'python-Pillow' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-Pillow", rpm:"python3-Pillow~7.2.0~150300.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Pillow-tk", rpm:"python3-Pillow-tk~7.2.0~150300.3.12.1", rls:"openSUSELeap15.5"))) {
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

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833257");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-45710", "CVE-2022-24713", "CVE-2022-31394", "CVE-2023-1521");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-06 20:57:37 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 08:01:05 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for sccache (SUSE-SU-2023:3526-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3526-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WBWIGGUFCJEAQJKPFGIJRDM5XHPJ4SFY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sccache'
  package(s) announced via the SUSE-SU-2023:3526-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sccache fixes the following issues:

  * Update to version 0.4.2.

  * CVE-2021-45710: Fixed a segmentation fault due to data race in tokio create.
      (bsc#1194119)

  * CVE-2022-24713: Fixed a ReDoS issue due to vulnerable regex create.
      (bsc#1196972)

  * CVE-2022-31394: Fixed a DoS issue due to the max header list size not
      settable. (bsc#1208553)

  * CVE-2023-1521: Fixed a local privilege escalation. (bsc#1212407)

  ##");

  script_tag(name:"affected", value:"'sccache' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"sccache", rpm:"sccache~0.4.2~3~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache-debuginfo", rpm:"sccache-debuginfo~0.4.2~3~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache", rpm:"sccache~0.4.2~3~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache-debuginfo", rpm:"sccache-debuginfo~0.4.2~3~150400.3.3.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"sccache", rpm:"sccache~0.4.2~3~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache-debuginfo", rpm:"sccache-debuginfo~0.4.2~3~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache", rpm:"sccache~0.4.2~3~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache-debuginfo", rpm:"sccache-debuginfo~0.4.2~3~150400.3.3.1", rls:"openSUSELeap15.5"))) {
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
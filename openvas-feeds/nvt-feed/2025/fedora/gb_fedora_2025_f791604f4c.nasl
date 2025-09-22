# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.102791604102499");
  script_cve_id("CVE-2025-5278");
  script_tag(name:"creation_date", value:"2025-05-30 04:06:29 +0000 (Fri, 30 May 2025)");
  script_version("2025-05-30T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-05-30 05:40:08 +0000 (Fri, 30 May 2025)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-27 21:15:23 +0000 (Tue, 27 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-f791604f4c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-f791604f4c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-f791604f4c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2368767");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coreutils' package(s) announced via the FEDORA-2025-f791604f4c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"sort: fix buffer under-read (CVE-2025-5278)");

  script_tag(name:"affected", value:"'coreutils' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"coreutils", rpm:"coreutils~9.6~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreutils-common", rpm:"coreutils-common~9.6~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreutils-debuginfo", rpm:"coreutils-debuginfo~9.6~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreutils-debugsource", rpm:"coreutils-debugsource~9.6~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreutils-single", rpm:"coreutils-single~9.6~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreutils-single-debuginfo", rpm:"coreutils-single-debuginfo~9.6~4.fc42", rls:"FC42"))) {
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

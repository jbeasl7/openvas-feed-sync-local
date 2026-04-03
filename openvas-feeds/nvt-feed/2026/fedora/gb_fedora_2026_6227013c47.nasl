# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.62270139947");
  script_cve_id("CVE-2026-33056");
  script_tag(name:"creation_date", value:"2026-04-02 04:48:18 +0000 (Thu, 02 Apr 2026)");
  script_version("2026-04-02T06:06:11+0000");
  script_tag(name:"last_modification", value:"2026-04-02 06:06:11 +0000 (Thu, 02 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-24 16:17:11 +0000 (Tue, 24 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-6227013c47)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-6227013c47");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-6227013c47");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-scx_layered' package(s) announced via the FEDORA-2026-6227013c47 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rebuilt with rust-tar 0.4.45 for CVE-2026-33056");

  script_tag(name:"affected", value:"'rust-scx_layered' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_layered", rpm:"rust-scx_layered~0.0.6~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_layered-debugsource", rpm:"rust-scx_layered-debugsource~0.0.6~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_layered", rpm:"scx_layered~0.0.6~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_layered-debuginfo", rpm:"scx_layered-debuginfo~0.0.6~8.fc42", rls:"FC42"))) {
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

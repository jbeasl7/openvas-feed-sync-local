# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827037");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2023-01-29 02:02:35 +0000 (Sun, 29 Jan 2023)");
  script_name("Fedora: Security Advisory for rust-libgit2-sys0.12 (FEDORA-2023-07cf2ae114)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-07cf2ae114");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3V42UEFD7WCRX2MP6HGDQ6F5JIIZIEWL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-libgit2-sys0.12'
  package(s) announced via the FEDORA-2023-07cf2ae114 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Native bindings to the libgit2 library.");

  script_tag(name:"affected", value:"'rust-libgit2-sys0.12' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys0.12", rpm:"rust-libgit2-sys0.12~0.12.26~5.fc36", rls:"FC36"))) {
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

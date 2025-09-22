# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.1019978979829945");
  script_tag(name:"creation_date", value:"2024-10-14 04:08:40 +0000 (Mon, 14 Oct 2024)");
  script_version("2024-10-15T05:05:49+0000");
  script_tag(name:"last_modification", value:"2024-10-15 05:05:49 +0000 (Tue, 15 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-ec78ab2c45)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ec78ab2c45");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-ec78ab2c45");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1547484");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316073");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'p7zip' package(s) announced via the FEDORA-2024-ec78ab2c45 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix wrapper to hide password from process history");

  script_tag(name:"affected", value:"'p7zip' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"p7zip", rpm:"p7zip~16.02~31.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-debugsource", rpm:"p7zip-debugsource~16.02~31.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-doc", rpm:"p7zip-doc~16.02~31.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-gui", rpm:"p7zip-gui~16.02~31.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-plugins", rpm:"p7zip-plugins~16.02~31.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-plugins-debuginfo", rpm:"p7zip-plugins-debuginfo~16.02~31.fc39", rls:"FC39"))) {
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

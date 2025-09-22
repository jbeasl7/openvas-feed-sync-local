# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.98399410181009781");
  script_cve_id("CVE-2024-38479", "CVE-2024-50305", "CVE-2024-50306");
  script_tag(name:"creation_date", value:"2024-11-22 04:08:53 +0000 (Fri, 22 Nov 2024)");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-b3c4e8da81)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-b3c4e8da81");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-b3c4e8da81");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2326136");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2326235");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2326240");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2326245");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trafficserver' package(s) announced via the FEDORA-2024-b3c4e8da81 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to upstream 9.2.6
- Backport fix for broken oubound TLS with OpenSSL 3.2+
- Resolves CVE-2024-38479, CVE-2024-50305, CVE-2024-50306");

  script_tag(name:"affected", value:"'trafficserver' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"trafficserver", rpm:"trafficserver~9.2.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-debuginfo", rpm:"trafficserver-debuginfo~9.2.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-debugsource", rpm:"trafficserver-debugsource~9.2.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-devel", rpm:"trafficserver-devel~9.2.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-perl", rpm:"trafficserver-perl~9.2.6~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-selinux", rpm:"trafficserver-selinux~9.2.6~2.fc40", rls:"FC40"))) {
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

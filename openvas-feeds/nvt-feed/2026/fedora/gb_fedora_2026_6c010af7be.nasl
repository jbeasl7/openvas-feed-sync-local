# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.69901097102798101");
  script_cve_id("CVE-2026-34073");
  script_tag(name:"creation_date", value:"2026-03-30 04:59:52 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-6c010af7be)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-6c010af7be");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-6c010af7be");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2451584");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-cryptography' package(s) announced via the FEDORA-2026-6c010af7be advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to v46.0.6

 This includes a single fix for security issue:

 * **SECURITY ISSUE**: Fixed a bug where name constraints were not applied
 to peer names during verification when the leaf certificate contains a
 wildcard DNS SAN. Ordinary X.509 topologies are not affected by this bug,
 including those used by the Web PKI. Credit to **Oleh Konko (1seal)** for
 reporting the issue. **CVE-2026-34073**");

  script_tag(name:"affected", value:"'python-cryptography' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography", rpm:"python-cryptography~46.0.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debugsource", rpm:"python-cryptography-debugsource~46.0.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~46.0.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography-debuginfo", rpm:"python3-cryptography-debuginfo~46.0.6~1.fc43", rls:"FC43"))) {
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

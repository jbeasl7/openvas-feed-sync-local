# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.342993999998102");
  script_cve_id("CVE-2024-3652");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-342c3cc98f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-342c3cc98f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-342c3cc98f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274448");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreswan' package(s) announced via the FEDORA-2024-342c3cc98f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for libreswan-4.15-2.fc41.

##### **Changelog**

```
* Sat Jun 22 2024 Paul Wouters <paul.wouters@aiven.io> - 4.15-2
- Add libreswan-4.15-ipsec_import.patch
* Sat Jun 22 2024 Paul Wouters <paul.wouters@aiven.io> - 4.15-1
- Update libreswan to 4.15 for CVE-2024-3652
- Resolves rhbz#2274448 CVE-2024-3652 libreswan: IKEv1 default AH/ESP
 responder can crash and restart
- Allow 'ipsec import' to try importing PKCS#12 non-interactively if there
 is no password

```");

  script_tag(name:"affected", value:"'libreswan' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~4.15~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreswan-debuginfo", rpm:"libreswan-debuginfo~4.15~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreswan-debugsource", rpm:"libreswan-debugsource~4.15~2.fc41", rls:"FC41"))) {
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

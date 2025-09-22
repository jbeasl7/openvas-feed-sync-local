# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.866999297944");
  script_cve_id("CVE-2024-24789", "CVE-2024-6104", "CVE-2024-6257");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-26 17:19:40 +0000 (Wed, 26 Jun 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-8669c2a944)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8669c2a944");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-8669c2a944");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292714");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2294007");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2294255");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opentofu' package(s) announced via the FEDORA-2024-8669c2a944 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for opentofu-1.7.3-3.fc41.

##### **Changelog**

```
* Sat Jul 27 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 1.7.3-3
- Fix for CVE-2024-6257 CVE-2024-6104 CVE-2024-24789 - Closes rhbz#2294255
 rhbz#2294007 rhbz#2292714

```");

  script_tag(name:"affected", value:"'opentofu' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"opentofu", rpm:"opentofu~1.7.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opentofu-debuginfo", rpm:"opentofu-debuginfo~1.7.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opentofu-debugsource", rpm:"opentofu-debugsource~1.7.3~3.fc41", rls:"FC41"))) {
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

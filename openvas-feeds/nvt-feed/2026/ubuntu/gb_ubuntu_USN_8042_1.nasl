# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8042.1");
  script_cve_id("CVE-2026-23948", "CVE-2026-24491", "CVE-2026-24675", "CVE-2026-24676", "CVE-2026-24677", "CVE-2026-24678", "CVE-2026-24679", "CVE-2026-24680", "CVE-2026-24681", "CVE-2026-24682", "CVE-2026-24683", "CVE-2026-24684");
  script_tag(name:"creation_date", value:"2026-02-17 04:37:15 +0000 (Tue, 17 Feb 2026)");
  script_version("2026-02-17T05:57:49+0000");
  script_tag(name:"last_modification", value:"2026-02-17 05:57:49 +0000 (Tue, 17 Feb 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-10 15:08:26 +0000 (Tue, 10 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8042-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8042-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8042-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp2, freerdp3' package(s) announced via the USN-8042-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FreeRDP incorrectly handled memory under certain
circumstances, which could lead to a NULL pointer dereference. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2026-23948)

It was discovered that FreeRDP did not correctly validate the size of
certain variables, which could cause a buffer overflow. An attacker could
possibly use this issue to cause a denial of service or execute arbitrary
code. This issue only affected FreeRDP3 in Ubuntu 24.04 LTS and Ubuntu
25.10. (CVE-2026-24491)

It was discovered that FreeRDP did not correctly validate the size of
certain variables, which could cause a buffer overflow. An attacker could
possibly use this issue to cause a denial of service or execute arbitrary
code. (CVE-2026-24675, CVE-2026-24679, CVE-2026-24682)

It was discovered that FreeRDP had a use after free vulnerability under
certain circumstances. An attacker could use this to cause a denial of
service or possibly execute arbitrary code. (CVE-2026-24676,
CVE-2026-24681)

It was discovered that FreeRDP did not correctly validate the size of
certain variables, which could cause a buffer overflow. An attacker could
possibly use this issue to cause a denial of service or execute arbitrary
code. This issue only affected Ubuntu 25.10. (CVE-2026-24677)

It was discovered that FreeRDP had a use after free vulnerability under
certain circumstances. An attacker could use this to cause a denial of
service or possibly execute arbitrary code. This issue only affected
Ubuntu 25.10. (CVE-2026-24678)

It was discovered that FreeRDP had a use after free vulnerability under
certain circumstances. An attacker could use this to cause a denial of
service or possibly execute arbitrary code. This issue only affected
FreeRDP3 in Ubuntu 24.04 LTS and Ubuntu 25.10. (CVE-2026-24680)

It was discovered that FreeRDP had a use after free vulnerability under
certain circumstances. An attacker could use this to cause a denial of
service or possibly execute arbitrary code. This issue only affected
Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS and Ubuntu 25.10.
(CVE-2026-24683, CVE-2026-24684)");

  script_tag(name:"affected", value:"'freerdp2, freerdp3' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-x11", ver:"2.2.0+dfsg1-0ubuntu0.18.04.4+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.2.0+dfsg1-0ubuntu0.18.04.4+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-x11", ver:"2.6.1+dfsg1-0ubuntu0.20.04.2+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.6.1+dfsg1-0ubuntu0.20.04.2+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-x11", ver:"2.6.1+dfsg1-3ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.6.1+dfsg1-3ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-x11", ver:"2.11.5+dfsg1-1ubuntu0.1~esm5", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp3-x11", ver:"3.5.1+dfsg1-0ubuntu1.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2t64", ver:"2.11.5+dfsg1-1ubuntu0.1~esm5", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp3-3", ver:"3.5.1+dfsg1-0ubuntu1.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"freerdp3-x11", ver:"3.16.0+dfsg-2ubuntu0.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp3-3", ver:"3.16.0+dfsg-2ubuntu0.1", rls:"UBUNTU25.10"))) {
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

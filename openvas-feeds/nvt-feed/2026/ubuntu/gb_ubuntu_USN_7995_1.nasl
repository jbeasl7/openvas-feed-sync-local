# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7995.1");
  script_cve_id("CVE-2026-21925", "CVE-2026-21932", "CVE-2026-21933", "CVE-2026-21945");
  script_tag(name:"creation_date", value:"2026-02-04 04:32:47 +0000 (Wed, 04 Feb 2026)");
  script_version("2026-02-04T05:55:03+0000");
  script_tag(name:"last_modification", value:"2026-02-04 05:55:03 +0000 (Wed, 04 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-20 22:15:57 +0000 (Tue, 20 Jan 2026)");

  script_name("Ubuntu: Security Advisory (USN-7995-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7995-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7995-1");
  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2026-01-20");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-25' package(s) announced via the USN-7995-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the RMI component of OpenJDK 25 would establish
RMI TCP endpoint connections to a remote host without setting an
endpoint identification algorithm. An unauthenticated remote attacker
could possibly use this issue to steal sensitive information.
(CVE-2026-21925)

Mingijung discovered that the AWT and JavaFX componenets of OpenJDK 25
could run programs if Desktop.browse() was supplied a filename as a
URI. An unauthenticated remote attacker could possibly use this issue
to execute arbitrary code. (CVE-2026-21932)

Zhihui Chen discovered that the Networking component of OpenJDK 25
was suceptible to a CRLF injection vulnerability via the HttpServer
class. An unauthenticated remote attacker could possibly use this
issue to modify files or leak sensitive information. (CVE-2026-21933)

Ireneusz Pastusiak discovered that the Security component of OpenJDK
25 failed to verify provided URIs point to a legitimate source when
AIA is enabled. An unauthenticated remote attacker could possibly
use this issue to redirect users to malicious hosts.
(CVE-2026-21945)

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]");

  script_tag(name:"affected", value:"'openjdk-25' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jdk", ver:"25.0.2+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jdk-headless", ver:"25.0.2+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jre", ver:"25.0.2+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jre-headless", ver:"25.0.2+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jre-zero", ver:"25.0.2+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jvmci-jdk", ver:"25.0.2+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jdk", ver:"25.0.2+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jdk-headless", ver:"25.0.2+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jre", ver:"25.0.2+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jre-headless", ver:"25.0.2+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jre-zero", ver:"25.0.2+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jvmci-jdk", ver:"25.0.2+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jdk", ver:"25.0.2+10-1~25.10", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jdk-headless", ver:"25.0.2+10-1~25.10", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jre", ver:"25.0.2+10-1~25.10", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jre-headless", ver:"25.0.2+10-1~25.10", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jre-zero", ver:"25.0.2+10-1~25.10", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-25-jvmci-jdk", ver:"25.0.2+10-1~25.10", rls:"UBUNTU25.10"))) {
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

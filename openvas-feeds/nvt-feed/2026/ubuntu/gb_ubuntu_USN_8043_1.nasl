# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8043.1");
  script_cve_id("CVE-2025-14831", "CVE-2025-9820");
  script_tag(name:"creation_date", value:"2026-02-17 04:37:15 +0000 (Tue, 17 Feb 2026)");
  script_version("2026-02-17T05:57:49+0000");
  script_tag(name:"last_modification", value:"2026-02-17 05:57:49 +0000 (Tue, 17 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-09 15:16:09 +0000 (Mon, 09 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8043-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8043-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8043-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls28' package(s) announced via the USN-8043-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tim Scheckenbach discovered that GnuTLS incorrectly handled malicious
certificates containing a large number of name constraints and subject
alternative names. A remote attacker could possibly use this issue to
cause GnuTLS to consume resources, resulting in a denial of service.
(CVE-2025-14831)

Luigino Camastra discovered that GnuTLS incorrectly handled certain PKCS11
token labels. A remote attacker could use this issue to cause GnuTLS to
crash, resulting in a denial of service, or possibly execute arbitrary
code. The default compiler options for affected releases should reduce the
vulnerability to a denial of service. (CVE-2025-9820)");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.7.3-4ubuntu1.8", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30t64", ver:"3.8.3-1.1ubuntu3.5", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30t64", ver:"3.8.9-3ubuntu2.1", rls:"UBUNTU25.10"))) {
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

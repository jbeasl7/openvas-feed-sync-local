# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8090.1");
  script_cve_id("CVE-2025-61984", "CVE-2025-61985", "CVE-2026-3497");
  script_tag(name:"creation_date", value:"2026-03-16 04:53:37 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8090-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8090-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the USN-8090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeremy Brown discovered that the OpenSSH GSSAPI Key Exchange incorrectly
handled disconnecting clients. In non-default configurations where the
GSSAPIKeyExchange setting is enabled, a remote attacker could use this
issue to cause OpenSSH to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2026-3497)

David Leadbeater discovered that OpenSSH incorrectly handled certain
control characters in usernames. When untrusted usernames and the
ProxyCommand are being used, an attacker could possibly use this issue to
execute arbitrary code. (CVE-2025-61984)

David Leadbeater discovered that OpenSSH incorrectly handled NULL
characters in ssh:// URIs. When the ProxyCommand is being used, an attacker
could possibly use this issue to execute arbitrary code. (CVE-2025-61985)");

  script_tag(name:"affected", value:"'openssh' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:8.9p1-3ubuntu0.14", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:8.9p1-3ubuntu0.14", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:9.6p1-3ubuntu13.15", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:9.6p1-3ubuntu13.15", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:10.0p1-5ubuntu5.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:10.0p1-5ubuntu5.1", rls:"UBUNTU25.10"))) {
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

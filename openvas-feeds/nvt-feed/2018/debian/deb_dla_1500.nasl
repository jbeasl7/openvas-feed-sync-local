# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891500");
  script_cve_id("CVE-2015-5352", "CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564", "CVE-2016-10009", "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-10708", "CVE-2016-1908", "CVE-2016-3115", "CVE-2016-6515", "CVE-2017-15906");
  script_tag(name:"creation_date", value:"2018-09-09 22:00:00 +0000 (Sun, 09 Sep 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-17 19:09:13 +0000 (Mon, 17 Apr 2017)");

  script_name("Debian: Security Advisory (DLA-1500-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1500-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1500-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DLA-1500-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in OpenSSH, a free implementation of the SSH protocol suite:

CVE-2015-5352

OpenSSH incorrectly verified time window deadlines for X connections. Remote attackers could take advantage of this flaw to bypass intended access restrictions. Reported by Jann Horn.

CVE-2015-5600

OpenSSH improperly restricted the processing of keyboard-interactive devices within a single connection, which could allow remote attackers to perform brute-force attacks or cause a denial of service, in a non-default configuration.

CVE-2015-6563

OpenSSH incorrectly handled usernames during PAM authentication. In conjunction with an additional flaw in the OpenSSH unprivileged child process, remote attackers could make use if this issue to perform user impersonation. Discovered by Moritz Jodeit.

CVE-2015-6564

Moritz Jodeit discovered a use-after-free flaw in PAM support in OpenSSH, that could be used by remote attackers to bypass authentication or possibly execute arbitrary code.

CVE-2016-1908

OpenSSH mishandled untrusted X11 forwarding when the X server disables the SECURITY extension. Untrusted connections could obtain trusted X11 forwarding privileges. Reported by Thomas Hoger.

CVE-2016-3115

OpenSSH improperly handled X11 forwarding data related to authentication credentials. Remote authenticated users could make use of this flaw to bypass intended shell-command restrictions. Identified by github.com/tintinweb.

CVE-2016-6515

OpenSSH did not limit password lengths for password authentication. Remote attackers could make use of this flaw to cause a denial of service via long strings.

CVE-2016-10009

Jann Horn discovered an untrusted search path vulnerability in ssh-agent allowing remote attackers to execute arbitrary local PKCS#11 modules by leveraging control over a forwarded agent-socket.

CVE-2016-10011

Jann Horn discovered that OpenSSH did not properly consider the effects of realloc on buffer contents. This may allow local users to obtain sensitive private-key information by leveraging access to a privilege-separated child process.

CVE-2016-10012

Guido Vranken discovered that the OpenSSH shared memory manager did not ensure that a bounds check was enforced by all compilers, which could allow local users to gain privileges by leveraging access to a sandboxed privilege-separation process.

CVE-2016-10708

NULL pointer dereference and daemon crash via an out-of-sequence NEWKEYS message.

CVE-2017-15906

Michal Zalewski reported that OpenSSH improperly prevent write operations in readonly mode, allowing attackers to create zero-length files.

For Debian 8 Jessie, these problems have been fixed in version 1:6.7p1-5+deb8u6.

We recommend that you upgrade your openssh packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:6.7p1-5+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client-udeb", ver:"1:6.7p1-5+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:6.7p1-5+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server-udeb", ver:"1:6.7p1-5+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-sftp-server", ver:"1:6.7p1-5+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh", ver:"1:6.7p1-5+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:6.7p1-5+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-krb5", ver:"1:6.7p1-5+deb8u6", rls:"DEB8"))) {
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

# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56209");
  script_cve_id("CVE-2006-0353");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-956-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-956-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-956-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-956");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lsh-utils' package(s) announced via the DSA-956-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Pfetzing discovered that lshd, a Secure Shell v2 (SSH2) protocol server, leaks a couple of file descriptors, related to the randomness generator, to user shells which are started by lshd. A local attacker can truncate the server's seed file, which may prevent the server from starting, and with some more effort, maybe also crack session keys.

After applying this update, you should remove the server's seed file (/var/spool/lsh/yarrow-seed-file) and then regenerate it with 'lsh-make-seed --server' as root.

For security reasons, lsh-make-seed really needs to be run from the console of the system you are running it on. If you run lsh-make-seed using a remote shell, the timing information lsh-make-seed uses for its random seed creation is likely to be screwed. If need be, you can generate the random seed on a different system than that which it will eventually be on, by installing the lsh-utils package and running 'lsh-make-seed -o my-other-server-seed-file'. You may then transfer the seed to the destination system as using a secure connection.

The old stable distribution (woody) may not be affected by this problem.

For the stable distribution (sarge) this problem has been fixed in version 2.0.1-3sarge1.

For the unstable distribution (sid) this problem has been fixed in version 2.0.1cdbs-4.

We recommend that you upgrade your lsh-server package.");

  script_tag(name:"affected", value:"'lsh-utils' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"lsh-client", ver:"2.0.1-3sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lsh-server", ver:"2.0.1-3sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lsh-utils", ver:"2.0.1-3sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lsh-utils-doc", ver:"2.0.1-3sarge1", rls:"DEB3.1"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703366");
  script_cve_id("CVE-2015-7236");
  script_tag(name:"creation_date", value:"2015-09-22 22:00:00 +0000 (Tue, 22 Sep 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-10-02 14:34:29 +0000 (Fri, 02 Oct 2015)");

  script_name("Debian: Security Advisory (DSA-3366-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3366-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3366-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3366");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rpcbind' package(s) announced via the DSA-3366-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A remotely triggerable use-after-free vulnerability was found in rpcbind, a server that converts RPC program numbers into universal addresses. A remote attacker can take advantage of this flaw to mount a denial of service (rpcbind crash).

For the oldstable distribution (wheezy), this problem has been fixed in version 0.2.0-8+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 0.2.1-6+deb8u1.

We recommend that you upgrade your rpcbind packages.");

  script_tag(name:"affected", value:"'rpcbind' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"rpcbind", ver:"0.2.0-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"rpcbind", ver:"0.2.1-6+deb8u1", rls:"DEB8"))) {
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

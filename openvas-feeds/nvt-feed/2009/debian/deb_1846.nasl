# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64557");
  script_cve_id("CVE-2009-2287");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1846-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1846-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1846-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1846");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kvm' package(s) announced via the DSA-1846-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matt T. Yourst discovered an issue in the kvm subsystem. Local users with permission to manipulate /dev/kvm can cause a denial of service (hang) by providing an invalid cr3 value to the KVM_SET_SREGS call.

For the stable distribution (lenny), these problems have been fixed in version 72+dfsg-5~lenny2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your kvm packages, and rebuild any kernel modules you have built from a kvm-source package version.");

  script_tag(name:"affected", value:"'kvm' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"kvm", ver:"72+dfsg-5~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kvm-source", ver:"72+dfsg-5~lenny2", rls:"DEB5"))) {
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

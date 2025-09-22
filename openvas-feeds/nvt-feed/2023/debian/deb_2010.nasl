# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2010");
  script_cve_id("CVE-2010-0298", "CVE-2010-0306", "CVE-2010-0309", "CVE-2010-0419");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2010-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2010-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2010-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2010");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kvm' package(s) announced via the DSA-2010-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in kvm, a full virtualization system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-0298

CVE-2010-0306

Gleb Natapov discovered issues in the KVM subsystem where missing permission checks (CPL/IOPL) permit a user in a guest system to denial of service a guest (system crash) or gain escalated privileges with the guest.

CVE-2010-0309

Marcelo Tosatti fixed an issue in the PIT emulation code in the KVM subsystem that allows privileged users in a guest domain to cause a denial of service (crash) of the host system.

CVE-2010-0419

Paolo Bonzini found a bug in KVM that can be used to bypass proper permission checking while loading segment selectors. This potentially allows privileged guest users to execute privileged instructions on the host system.

For the stable distribution (lenny), this problem has been fixed in version 72+dfsg-5~lenny5.

For the testing distribution (squeeze), and the unstable distribution (sid), these problems will be addressed within the linux-2.6 package.

We recommend that you upgrade your kvm package.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kvm", ver:"72+dfsg-5~lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kvm-source", ver:"72+dfsg-5~lenny5", rls:"DEB5"))) {
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

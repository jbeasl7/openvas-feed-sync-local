# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61368");
  script_cve_id("CVE-2008-1447");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2008-07-09 15:22:00 +0000 (Wed, 09 Jul 2008)");

  script_name("Debian: Security Advisory (DSA-1617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1617-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1617-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1617");
  script_xref(name:"URL", value:"https://wiki.debian.org/SELinux/Issues/BindPortRandomization");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'refpolicy' package(s) announced via the DSA-1617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In DSA-1603-1, Debian released an update to the BIND 9 domain name server, which introduced UDP source port randomization to mitigate the threat of DNS cache poisoning attacks (identified by the Common Vulnerabilities and Exposures project as CVE-2008-1447). The fix, while correct, was incompatible with the version of SELinux Reference Policy shipped with Debian Etch, which did not permit a process running in the named_t domain to bind sockets to UDP ports other than the standard 'domain' port (53). The incompatibility affects both the 'targeted' and 'strict' policy packages supplied by this version of refpolicy.

This update to the refpolicy packages grants the ability to bind to arbitrary UDP ports to named_t processes. When installed, the updated packages will attempt to update the bind policy module on systems where it had been previously loaded and where the previous version of refpolicy was 0.0.20061018-5 or below.

Because the Debian refpolicy packages are not yet designed with policy module upgradeability in mind, and because SELinux-enabled Debian systems often have some degree of site-specific policy customization, it is difficult to assure that the new bind policy can be successfully upgraded. To this end, the package upgrade will not abort if the bind policy update fails. The new policy module can be found at /usr/share/selinux/refpolicy-targeted/bind.pp after installation. Administrators wishing to use the bind service policy can reconcile any policy incompatibilities and install the upgrade manually thereafter. A more detailed discussion of the corrective procedure may be found on [link moved to references].

For the stable distribution (etch), this problem has been fixed in version 0.0.20061018-5.1+etch1.

The unstable distribution (sid) is not affected, as subsequent refpolicy releases have incorporated an analogous change.

We recommend that you upgrade your refpolicy packages.");

  script_tag(name:"affected", value:"'refpolicy' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"selinux-policy-refpolicy-dev", ver:"0.0.20061018-5.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"selinux-policy-refpolicy-doc", ver:"0.0.20061018-5.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"selinux-policy-refpolicy-src", ver:"0.0.20061018-5.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"selinux-policy-refpolicy-strict", ver:"0.0.20061018-5.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"selinux-policy-refpolicy-targeted", ver:"0.0.20061018-5.1+etch1", rls:"DEB4"))) {
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

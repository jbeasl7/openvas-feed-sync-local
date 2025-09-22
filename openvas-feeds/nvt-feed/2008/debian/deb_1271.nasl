# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58322");
  script_cve_id("CVE-2007-1507");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1271-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1271-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1271-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1271");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DSA-1271-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A design error has been identified in the OpenAFS, a cross-platform distributed filesystem included with Debian.

OpenAFS historically has enabled setuid filesystem support for the local cell. However, with its existing protocol, OpenAFS can only use encryption, and therefore integrity protection, if the user is authenticated. Unauthenticated access doesn't do integrity protection. The practical result is that it's possible for an attacker with knowledge of AFS to forge an AFS FetchStatus call and make an arbitrary binary file appear to an AFS client host to be setuid. If they can then arrange for that binary to be executed, they will be able to achieve privilege escalation.

OpenAFS 1.3.81-3sarge2 changes the default behavior to disable setuid files globally, including the local cell. It is important to note that this change will not take effect until the AFS kernel module, built from the openafs-modules-source package, is rebuilt and loaded into your kernel. As a temporary workaround until the kernel module can be reloaded, setuid support can be manually disabled for the local cell by running the following command as root

fs setcell -cell <localcell> -nosuid

Following the application of this update, if you are certain there is no security risk of an attacker forging AFS fileserver responses, you can re-enable setuid status selectively with the following command, however this should not be done on sites that are visible to the Internet

fs setcell -cell <localcell> -suid

For the stable distribution (sarge), this problem has been fixed in version 1.3.81-3sarge2.

For the unstable distribution (sid) and the upcoming stable distribution (etch), this problem will be fixed in version 1.4.2-6.

We recommend that you upgrade your openafs package.");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.3.81-3sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.3.81-3sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-client", ver:"1.3.81-3sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.3.81-3sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.3.81-3sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.3.81-3sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.3.81-3sarge2", rls:"DEB3.1"))) {
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

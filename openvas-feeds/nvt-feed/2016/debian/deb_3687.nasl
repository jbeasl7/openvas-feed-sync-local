# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703687");
  script_cve_id("CVE-2016-1951");
  script_tag(name:"creation_date", value:"2016-10-04 22:00:00 +0000 (Tue, 04 Oct 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-10 14:04:04 +0000 (Wed, 10 Aug 2016)");

  script_name("Debian: Security Advisory (DSA-3687-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3687-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3687-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3687");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nspr' package(s) announced via the DSA-3687-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were reported in NSPR, a library to abstract over operating system interfaces developed by the Mozilla project.

CVE-2016-1951

q1 reported that the NSPR implementation of sprintf-style string formatting function miscomputed memory allocation sizes, potentially leading to heap-based buffer overflows

The second issue concerns environment variable processing in NSPR. The library did not ignore environment variables used to configuring logging and tracing in processes which underwent a SUID/SGID/AT_SECURE transition at process start. In certain system configurations, this allowed local users to escalate their privileges.

In addition, this nspr update contains further stability and correctness fixes and contains support code for an upcoming nss update.

For the stable distribution (jessie), these problems have been fixed in version 2:4.12-1+debu8u1.

For the unstable distribution (sid), these problems have been fixed in version 2:4.12-1.

We recommend that you upgrade your nspr packages.");

  script_tag(name:"affected", value:"'nspr' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4", ver:"2:4.12-1+debu8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-0d", ver:"2:4.12-1+debu8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-dbg", ver:"2:4.12-1+debu8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-dev", ver:"2:4.12-1+debu8u1", rls:"DEB8"))) {
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

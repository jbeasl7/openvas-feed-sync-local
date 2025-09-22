# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57483");
  script_cve_id("CVE-2006-4924", "CVE-2006-5051");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:36:44 +0000 (Fri, 02 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1189-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1189-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1189-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1189");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh-krb5' package(s) announced via the DSA-1189-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in OpenSSH, a free implementation of the Secure Shell protocol, which may lead to denial of service and potentially the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-4924

Tavis Ormandy of the Google Security Team discovered a denial of service vulnerability in the mitigation code against complexity attacks, which might lead to increased CPU consumption until a timeout is triggered. This is only exploitable if support for SSH protocol version 1 is enabled.

CVE-2006-5051

Mark Dowd discovered that insecure signal handler usage could potentially lead to execution of arbitrary code through a double free. The Debian Security Team doesn't believe the general openssh package without Kerberos support to be exploitable by this issue. However, due to the complexity of the underlying code we will issue an update to rule out all eventualities.

For the stable distribution (sarge) these problems have been fixed in version 3.8.1p1-7sarge1.

For the unstable distribution (sid) these problems have been fixed in version 4.3p2-4 of openssh. openssh-krb5 will soon be converted towards a transitional package against openssh.

We recommend that you upgrade your openssh-krb5 packages.");

  script_tag(name:"affected", value:"'openssh-krb5' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ssh-krb5", ver:"3.8.1p1-7sarge1", rls:"DEB3.1"))) {
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

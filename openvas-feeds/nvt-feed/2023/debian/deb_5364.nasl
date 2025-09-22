# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705364");
  script_cve_id("CVE-2022-25147");
  script_tag(name:"creation_date", value:"2023-02-28 02:00:08 +0000 (Tue, 28 Feb 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-17 19:42:25 +0000 (Wed, 17 May 2023)");

  script_name("Debian: Security Advisory (DSA-5364-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5364-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5364-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5364");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/apr-util");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apr-util' package(s) announced via the DSA-5364-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ronald Crane discovered that missing input sanitizing in the apr_base64 functions of apr-util, the Apache Portable Runtime utility library, may result in denial of service or potentially the execution of arbitrary code.

For the stable distribution (bullseye), this problem has been fixed in version 1.6.1-5+deb11u1.

We recommend that you upgrade your apr-util packages.

For the detailed security status of apr-util please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'apr-util' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbd-mysql", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbd-odbc", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbd-pgsql", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbd-sqlite3", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-ldap", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
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

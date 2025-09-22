# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703798");
  script_cve_id("CVE-2017-6307", "CVE-2017-6308", "CVE-2017-6309", "CVE-2017-6310");
  script_tag(name:"creation_date", value:"2017-02-28 23:00:00 +0000 (Tue, 28 Feb 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-24 19:47:55 +0000 (Fri, 24 Feb 2017)");

  script_name("Debian: Security Advisory (DSA-3798-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3798-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3798-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3798");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tnef' package(s) announced via the DSA-3798-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eric Sesterhenn, from X41 D-Sec GmbH, discovered several vulnerabilities in tnef, a tool used to unpack MIME attachments of type application/ms-tnef. Multiple heap overflows, type confusions and out of bound reads and writes could be exploited by tricking a user into opening a malicious attachment. This would result in denial of service via application crash, or potential arbitrary code execution.

For the stable distribution (jessie), these problems have been fixed in version 1.4.9-1+deb8u1.

We recommend that you upgrade your tnef packages.");

  script_tag(name:"affected", value:"'tnef' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"tnef", ver:"1.4.9-1+deb8u1", rls:"DEB8"))) {
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

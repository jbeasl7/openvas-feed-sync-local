# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705200");
  script_cve_id("CVE-2021-46828");
  script_tag(name:"creation_date", value:"2022-08-08 01:00:19 +0000 (Mon, 08 Aug 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-01 16:51:11 +0000 (Mon, 01 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-5200-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5200-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5200-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5200");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libtirpc");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libtirpc' package(s) announced via the DSA-5200-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libtirpc, a transport-independent RPC library, does not properly handle idle TCP connections. A remote attacker can take advantage of this flaw to cause a denial of service.

For the stable distribution (bullseye), this problem has been fixed in version 1.3.1-1+deb11u1.

We recommend that you upgrade your libtirpc packages.

For the detailed security status of libtirpc please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libtirpc' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtirpc-common", ver:"1.3.1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtirpc-dev", ver:"1.3.1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtirpc3", ver:"1.3.1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtirpc3-udeb", ver:"1.3.1-1+deb11u1", rls:"DEB11"))) {
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

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892984");
  script_cve_id("CVE-2022-26110");
  script_tag(name:"creation_date", value:"2022-04-20 01:00:06 +0000 (Wed, 20 Apr 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-13 16:20:12 +0000 (Wed, 13 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-2984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2984-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2984-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/condor");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'condor' package(s) announced via the DLA-2984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jaime Frey discovered a flaw in HTCondor, a distributed workload management system. An attacker need only have READ-level authorization to a vulnerable daemon using the CLAIMTOBE authentication method. This means they are able to run tools like condor_q or condor_status. Many pools do not restrict who can issue READ-level commands, and CLAIMTOBE is allowed for READ-level commands in the default configuration. Thus, it is likely that an attacker could execute this command remotely from an untrusted network, unless prevented by a firewall or other network-level access controls.

For Debian 9 stretch, this problem has been fixed in version 8.4.11~dfsg.1-1+deb9u2.

We recommend that you upgrade your condor packages.

For the detailed security status of condor please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'condor' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"condor", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"condor-dbg", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"condor-dev", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"condor-doc", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"htcondor", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"htcondor-dbg", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"htcondor-dev", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"htcondor-doc", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclassad-dev", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclassad7", ver:"8.4.11~dfsg.1-1+deb9u2", rls:"DEB9"))) {
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

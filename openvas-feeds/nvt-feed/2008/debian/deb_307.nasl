# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53598");
  script_cve_id("CVE-2003-0360", "CVE-2003-0361", "CVE-2003-0362");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-307");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-307");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-307");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gps' package(s) announced via the DSA-307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gPS is a graphical application to watch system processes. In release 1.1.0 of the gps package, several security vulnerabilities were fixed, as detailed in the changelog:

bug fix on rgpsp connection source acceptation policy (it was allowing any host to connect even when the /etc/rgpsp.conf file told otherwise). It is working now, but on any real ('production') network I suggest you use IP filtering to enforce the policy (like ipchains or iptables).

Several possibilities of buffer overflows have been fixed. Thanks to Stanislav Ievlev from ALT-Linux for pointing a lot of them.

fixed misformatting of command line parameters in rgpsp protocol (command lines with newlines would break the protocol).

fixed buffer overflow bug that caused rgpsp to SIGSEGV when stating processes with large command lines (>128 chars) [Linux only].

All of these problems affect Debian's gps package version 0.9.4-1 in Debian woody. Debian potato also contains a gps package (version 0.4.1-2), but it is not affected by these problems, as the relevant functionality is not implemented in that version.

For the stable distribution (woody) these problems have been fixed in version 0.9.4-1woody1.

The old stable distribution (potato) is not affected by these problems.

For the unstable distribution (sid) these problems are fixed in version 1.1.0-1.

We recommend that you update your gps package.");

  script_tag(name:"affected", value:"'gps' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"gps", ver:"0.9.4-1woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rgpsp", ver:"0.9.4-1woody1", rls:"DEB3.0"))) {
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

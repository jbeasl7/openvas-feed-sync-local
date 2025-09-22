# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53432");
  script_cve_id("CVE-2002-1232");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-180)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-180");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/DSA-180");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-180");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nis' package(s) announced via the DSA-180 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thorsten Kukuck discovered a problem in the ypserv program which is part of the Network Information Services (NIS). A memory leak in all versions of ypserv prior to 2.5 is remotely exploitable. When a malicious user could request a non-existing map the server will leak parts of an old domainname and mapname.

This problem has been fixed in version 3.9-6.1 for the current stable distribution (woody), in version 3.8-2.1 for the old stable distribution (potato) and in version 3.9-6.2 for the unstable distribution (sid).

We recommend that you upgrade your nis package.");

  script_tag(name:"affected", value:"'nis' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nis", ver:"3.9-6.1", rls:"DEB3.0"))) {
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

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53646");
  script_version("2024-09-10T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-09-10 05:05:42 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0466");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 15:50:15 +0000 (Thu, 08 Feb 2024)");
  script_name("Debian Security Advisory DSA 357-1 (wu-ftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20357-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8315");
  script_tag(name:"insight", value:"iSEC Security Research reports that wu-ftpd contains an off-by-one bug
in the fb_realpath function which could be exploited by a logged-in user
(local or anonymous) to gain root privileges. A demonstration exploit is
reportedly available.

For the current stable distribution (woody) this problem has been fixed
in version 2.6.2-3woody1.

For the unstable distribution (sid) an update will be available shortly.

We recommend you upgrade your wu-ftpd package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to wu-ftpd
announced via advisory DSA 357-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"wu-ftpd-academ", ver:"2.6.2-3woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wu-ftpd", ver:"2.6.2-3woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

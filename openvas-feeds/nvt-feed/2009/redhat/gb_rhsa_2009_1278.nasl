# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64806");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
  script_cve_id("CVE-2007-2348");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:1278");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1278.

LFTP is a sophisticated file transfer program for the FTP and HTTP
protocols. Like bash, it has job control and uses the readline library for
input. It has bookmarks, built-in mirroring, and can transfer several files
in parallel. It is designed with reliability in mind.

It was discovered that lftp did not properly escape shell metacharacters
when generating shell scripts using the mirror --script command. A
mirroring script generated to download files from a malicious FTP server
could allow an attacker controlling the FTP server to run an arbitrary
command as the user running lftp. (CVE-2007-2348)

Note: This update upgrades LFTP from version 3.7.3 to upstream version
3.7.11, which incorporates a number of further bug fixes to those noted
above. For details regarding these fixes, refer to the
/usr/share/doc/lftp-3.7.11/NEWS file after installing this update.
(BZ#308721)

All LFTP users are advised to upgrade to this updated package, which
resolves these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1278.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#low");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"lftp", rpm:"lftp~3.7.11~4.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lftp-debuginfo", rpm:"lftp-debuginfo~3.7.11~4.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}

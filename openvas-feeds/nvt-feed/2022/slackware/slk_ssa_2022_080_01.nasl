# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.080.01");
  script_cve_id("CVE-2021-25220", "CVE-2022-0396");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 18:14:39 +0000 (Mon, 28 Nov 2022)");

  script_name("Slackware: Security Advisory (SSA:2022-080-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2022-080-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.382950");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SSA:2022-080-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New bind packages are available for Slackware 15.0, since the previous patch
mistakenly moved to a newer BIND branch. These packages do not fix any security
issues that weren't already fixed in the bind-9.18.1 packages, which have been
moved into /testing, but the BIND 9.16 LTS version is the correct one for
Slackware 15.0.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/bind-9.16.27-i586-1_slack15.0.txz: Upgraded.
 Sorry folks, I had not meant to bump BIND to the newer branch. I've moved
 the other packages into /testing. Thanks to Nobby6 for pointing this out.
 This update fixes bugs and the following security issues:
 A synchronous call to closehandle_cb() caused isc__nm_process_sock_buffer()
 to be called recursively, which in turn left TCP connections hanging in the
 CLOSE_WAIT state blocking indefinitely when out-of-order processing was
 disabled.
 The rules for acceptance of records into the cache have been tightened to
 prevent the possibility of poisoning if forwarders send records outside
 the configured bailiwick.
 For more information, see:
 [links moved to references]
 (* Security fix *)
testing/packages/bind-9.18.1-i586-1_slack15.0.txz: Moved.
+--------------------------+");

  script_tag(name:"affected", value:"'bind' package(s) on Slackware 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.16.27-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.16.27-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

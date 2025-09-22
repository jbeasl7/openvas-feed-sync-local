# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123963");
  script_cve_id("CVE-2011-1749");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0310)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0310");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0310.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfs-utils' package(s) announced via the ELSA-2012-0310 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.0.9-60.0.1.el5]
- Add support for resvport for unmonting [orabug 13567018]

[1.0.9-60]
- Updated idmapd.conf and idmapd.conf.man to reflect the
 static user name mapping (502707)
- Fixed an umount regression introduced by bz 513094 (bz 781931)

[1.0.9-59]
- gss: turned of even more excessive syslogs (bz 593097)
- mount.nfs: Ignored the SIGXFSZ when handling RLIMIT_FSIZE changes (bz 697979)

[1.0.9-58]
- gss: turned off more excessive syslogs (bz 593097)
- initfiles: more initscripts improvements (bz 710020)
- specfile: correct typo when nfsnobodys gid already exists (bz 729603)

[1.0.9-57]
- Mount fails to anticipate RLIMIT_FSIZE (bz 697979,CVE-2011-1749)

[1.0.9-56]
- Removed sim crash support (bz 600497)
- initfiles: more initscripts improvements (bz 710020)
- mount: Don't wait for TCP to timeout twice (bz 736677)

[1.0.9-55]
- mount: fixed the -o retry option to retry the given amount (bz 736677)
- manpage: removed the -o fsc option (bz 715523)
- nfsstat: show v4 mounts with -m flag (bz 712438)
- mount: allow insecure ports with mounts (bz 513094)
- gss: turned off excessive syslogs (bz 593097)
- mountd: allow v2 and v3 to be disabled (bz 529588)
- specfile: make sure nfsnobodys gid changes when it exists (bz 729603)
- initfiles: initscripts improvements (bz 710020)");

  script_tag(name:"affected", value:"'nfs-utils' package(s) on Oracle Linux 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.0.9~60.0.1.el5", rls:"OracleLinux5"))) {
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

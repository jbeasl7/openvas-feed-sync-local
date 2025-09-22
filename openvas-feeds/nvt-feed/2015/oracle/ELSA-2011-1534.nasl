# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122043");
  script_cve_id("CVE-2011-1749", "CVE-2011-2500");
  script_tag(name:"creation_date", value:"2015-10-06 11:12:07 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-1534)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1534");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1534.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfs-utils' package(s) announced via the ELSA-2011-1534 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.2.3-15]
- mout.nfs: Don't roll back to IPv4 when IPv6 fails (bz 744657)
- rpcdebug: Added pNFS and FSCache debugging (bz 747400)

[1.2.3-14]
- mount.nfs: Backported how upstream handles the SIGXFSZ signal (bz 697981)

[1.2.3-13]
- mount.nfs: Reworked the code that deals with RLIMIT_FSIZE (bz 697981)

[1.2.3-12]
- Removed the stripping of debugging information from rpcdebug (bz 729001)

[1.2.3-11]
- mount.nfs: Fixed problem in mount error verbosity patch (bz 731693)

[1.2.3-10]
- mount.nfs: add error verbosity to invalid versions (bz 731693)

[1.2.3-9]
- umount.nfs: Got IPV6 unmounts working again (bz 732673)
- mountd: return multiple hosts exporting the same directory (bz 726112)
- mount: Better error message for invalid version (bz 723780)

[1.2.3-8]
- initscripts: just try to mount rpc_pipefs always (bz 692702)
- Rely on crypto module autoloading in init scripts
- svcgssd: Document '-n' for svcgssd (bz 697359)
- mount.nfs: anticipate RLIMIT_FSIZE (bz 697981)
- exportfs manpage: Ipv6 update (bz 715078)
- mountd: Stop segfault in mtab code (bz 723438)
- exportfs: wildcards in exports can lead to unintended mounts (bz 715391)
- umount: allow spaces in unmount paths (bz 702273)
- specfile: reordered how libgssglue is linked in (bz 720479)");

  script_tag(name:"affected", value:"'nfs-utils' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.2.3~15.el6", rls:"OracleLinux6"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122027");
  script_cve_id("CVE-2011-1773");
  script_tag(name:"creation_date", value:"2015-10-06 11:11:53 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-1615)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1615");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1615.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virt-v2v' package(s) announced via the ELSA-2011-1615 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.8.3-5]
- Fix regression when converting Win7 32 bit to RHEV (RHBZ#738236)

[0.8.3-4]
[element]

[0.8.3-3]
- Add missing dependency on new Sys::Virt

[0.8.3-2]
- Fix for CVE-2011-1773
- Document limitations wrt Windows Recovery Console

[0.8.3-1]
- Include missing virt-v2v.db
- Rebase to upstream release 0.8.3

[0.8.2-2]
- Split configuration into /etc/virt-v2v.conf and /var/lib/virt-v2v/virt-v2v.db
- Improve usability as non-root user (RHBZ#671094)
- Update man pages to use -os as appropriate (RHBZ#694370)
- Warn if user specifies both -n and -b (RHBZ#700759)
- Fix cleanup when multiboot OS is detected (RHBZ#702007)
- Ensure the cirrus driver is installed if required (RHBZ#708961)
- Remove unnecessary dep on perl(IO::Handle)
- Fix conversion of xen guests using aio storage backend.
- Suppress warning for chainloader grub entries.
- Only configure a single scsi_hostadapter for converted VMware guests.

[0.8.2-1]
- Rebase to upstream release 0.8.2

[0.7.1-4]
- Fix detection of Windows XP Pro x64 (RHBZ#679017)
- Fix error message when converting Red Hat Desktop (RHBZ#678950)");

  script_tag(name:"affected", value:"'virt-v2v' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"virt-v2v", rpm:"virt-v2v~0.8.3~5.el6", rls:"OracleLinux6"))) {
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

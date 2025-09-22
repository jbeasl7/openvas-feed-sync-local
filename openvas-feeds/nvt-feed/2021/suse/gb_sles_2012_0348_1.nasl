# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0348.1");
  script_cve_id("CVE-2010-0787", "CVE-2010-1642", "CVE-2010-2063", "CVE-2010-3069", "CVE-2011-0719", "CVE-2011-2694", "CVE-2012-0870");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0348-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0348-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120348-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Samba' package(s) announced via the SUSE-SU-2012:0348-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This Samba file server update fixes various security issues:

 * CVE-2012-0870: A heap-based buffer overflow that could be exploited by remote, unauthenticated attackers to crash the smbd daemon or potentially execute arbitrary code via specially crafted SMB AndX request packets.
 * CVE-2011-2694: A cross site scripting problem in SWAT was fixed.
 * CVE-2011-0719: Fixed a possible denial of service caused by memory corruption.
 * CVE-2010-3069: Fix buffer overflow in sid_parse() to correctly check the input lengths when reading a binary representation of a Windows Security ID (SID).
 * CVE-2010-2063: Addressed possible buffer overrun in chain_reply code of pre-3.4 versions.
 * CVE-2010-1642: An uninitialized variable read could have caused an smbd crash.
 * CVE-2010-0787: Take extra care that a mount point of mount.cifs isn't changed during mount,

Also the following bugs have been fixed:

 * Add Provides samba-client-gplv2 and samba-doc-gplv2 to pre-3.2 versions, (bnc#652620).
 * Initialize workgroup of nmblookup as empty string.
 * Fix trusts with Windows 2008R2 DCs, (bnc#613459),
(bnc#599873), (bnc#592198), (bso#6697).
 * Document 'wide links' defaults to 'no' in the smb.conf man page for versions pre-3.4.6, (bnc#577868).
 * Allow forced pw change even with min pw age,
(bnc#561894).

Security Issue reference:

 * CVE-2012-0870
>");

  script_tag(name:"affected", value:"'Samba' package(s) on SUSE Linux Enterprise Server 10-SP2.");

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

if(release == "SLES10.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"cifs-mount", rpm:"cifs-mount~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmsrpc", rpm:"libmsrpc~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmsrpc-devel", rpm:"libmsrpc-devel~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-32bit", rpm:"libsmbclient-32bit~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-32bit", rpm:"samba-32bit~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-krb-printing", rpm:"samba-krb-printing~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-vscan", rpm:"samba-vscan~0.3.6b~42.85.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~3.0.32~0.20.1", rls:"SLES10.0SP2"))) {
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

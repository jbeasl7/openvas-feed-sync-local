# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2304.1");
  script_cve_id("CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-5330", "CVE-2015-8467");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-30 16:32:32 +0000 (Wed, 30 Dec 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2304-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152304-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/295284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/872912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958586");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-December/001740.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ldb, samba, talloc, tdb, tevent' package(s) announced via the SUSE-SU-2015:2304-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ldb, samba, talloc, tdb, tevent fixes the following security issues:

- ldb was updated to version 1.1.24.
 + Fix ldap \00 search expression attack dos, CVE-2015-3223, (bso#11325)
 + Fix remote read memory exploit in ldb, CVE-2015-5330, (bso#11599)
 + Move ldb_(un)pack_data into ldb_module.h for testing
 + Fix installation of _ldb_text.py
 + Fix propagation of ldb errors through tdb
 + Fix bug triggered by having an empty message in database during search

- Move the ldb-cmdline library to the ldb-tools package as the packaged
 binaries depend on it.

- Update the samba library distribution key file 'ldb.keyring', (bso#945116).

Samba was updated to fix these issues:
- Malicious request can cause samba ldap server to hang, spinning using cpu,
 CVE-2015-3223, (bso#11325), (bsc#958581).
- Remote read memory exploit in ldb, cve-2015-5330, (bso#11599), (bsc#958586).
- Insufficient symlink verification (file access outside the share),
 CVE-2015-5252, (bso#11395), (bsc#958582).
- No man in the middle protection when forcing smb encryption on the client
 side, CVE-2015-5296, (bso#11536), (bsc#958584).
- Currently the snapshot browsing is not secure thru windows previous version
 (shadow_copy2), CVE-2015-5299, (bso#11529), (bsc#958583).
- Fix microsoft ms15-096 to prevent machine accounts from being changed into
 user accounts, CVE-2015-8467, (bso#11552), (bsc#958585).
- Changing log level of two entries to from 1 to 3, (bso#9912).
- Vfs_gpfs: re-enable share modes, (bso#11243).
- Wafsamba: also build libraries with relro protection, (bso#11346).
- Ctdb: strip trailing spaces from nodes file, (bso#11365).
- S3-smbd: fix old dos client doing wildcard delete - gives a attribute type
 of zero, (bso#11452).
- Nss_wins: do not run into use after free issues when we access memory
 allocated on the globals and the global being reinitialized, (bso#11563).
- Async_req: fix non-blocking connect(), (bso#11564).
- Auth: gensec: fix a memory leak, (bso#11565).
- Lib: util: make non-critical message a warning, (bso#11566).
- Fix winbindd crashes with samlogon for trusted domain user, (bso#11569),
 (bsc#949022).
- Smbd: send smb2 oplock breaks unencrypted, (bso#11570).
- Ctdb: open the ro tracking db with perms 0600 instead of 0000, (bso#11577).
- Manpage: correct small typo error, (bso#11584).
- S3: smbd: if ea's are turned off on a share don't allow an smb2 create
 containing them, (bso#11589).
- Backport some valgrind fixes from upstream master, (bso#11597).
- S3: smbd: have_file_open_below() fails to enumerate open files below an open
 directory handle, (bso#11615).
- Docs: fix some typos in the idmap config section of man 5 smb.conf,
 (bso#11619).
- Cleanup and enhance the pidl sub package.
- S3: smbd: fix our access-based enumeration on 'hide unreadable' to match
 Windows, (bso#10252).
- Smbd: fix file name buflen and padding in notify repsonse, (bso#10634).
- Kerberos: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ldb, samba, talloc, tdb, tevent' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit", rpm:"libdcerpc-binding0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0", rpm:"libdcerpc-binding0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit", rpm:"libdcerpc0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0", rpm:"libdcerpc0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgensec0-32bit", rpm:"libgensec0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgensec0", rpm:"libgensec0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb1", rpm:"libldb1~1.1.24~4.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb1-32bit", rpm:"libldb1-32bit~1.1.24~4.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit", rpm:"libndr-krb5pac0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0", rpm:"libndr-krb5pac0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit", rpm:"libndr-nbt0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0", rpm:"libndr-nbt0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit", rpm:"libndr-standard0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0", rpm:"libndr-standard0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit", rpm:"libndr0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0", rpm:"libndr0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit", rpm:"libnetapi0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpdb0-32bit", rpm:"libpdb0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpdb0", rpm:"libpdb0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libregistry0", rpm:"libregistry0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit", rpm:"libsamba-credentials0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0", rpm:"libsamba-credentials0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit", rpm:"libsamba-hostconfig0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0", rpm:"libsamba-hostconfig0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit", rpm:"libsamba-util0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0", rpm:"libsamba-util0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit", rpm:"libsamdb0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0", rpm:"libsamdb0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-raw0-32bit", rpm:"libsmbclient-raw0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-raw0", rpm:"libsmbclient-raw0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-32bit", rpm:"libsmbclient0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit", rpm:"libsmbconf0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0", rpm:"libsmbconf0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0-32bit", rpm:"libsmbldap0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0", rpm:"libsmbldap0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc2", rpm:"libtalloc2~2.1.5~3.4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc2-32bit", rpm:"libtalloc2-32bit~2.1.5~3.4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtdb1", rpm:"libtdb1~1.3.8~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtdb1-32bit", rpm:"libtdb1-32bit~1.3.8~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit", rpm:"libtevent-util0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0", rpm:"libtevent-util0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent0", rpm:"libtevent0~0.9.26~3.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent0-32bit", rpm:"libtevent0-32bit~0.9.26~3.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pytalloc", rpm:"pytalloc~2.1.5~3.4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pytalloc-32bit", rpm:"pytalloc-32bit~2.1.5~3.4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-32bit", rpm:"samba-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.1.12~18.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdb-tools", rpm:"tdb-tools~1.3.8~2.3.1", rls:"SLES12.0"))) {
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

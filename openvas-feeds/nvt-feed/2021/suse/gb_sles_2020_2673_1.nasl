# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2673.1");
  script_cve_id("CVE-2019-10197", "CVE-2019-10218", "CVE-2019-14833", "CVE-2019-14847", "CVE-2019-14861", "CVE-2019-14870", "CVE-2019-14902", "CVE-2019-14907", "CVE-2019-19344", "CVE-2020-10700", "CVE-2020-10704", "CVE-2020-10730", "CVE-2020-10745", "CVE-2020-10760", "CVE-2020-14303");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-15 17:46:01 +0000 (Wed, 15 Jul 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2673-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2673-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202673-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174120");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-September/007440.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2020:2673-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba to version 4.10.17 fixes the following issues:

- Fixed net command unable to negotiate SMB2, (bsc#1174120),

- Update to 4.10.17
 - CVE-2020-10745: Invalid DNS or NBT queries containing dots use
 several seconds of CPU each, (bso#14378), (bsc#1173160).
 - CVE-2020-10730: NULL de-reference in AD DC LDAP server when ASQ
 and VLV combined, (bso#14364), (bsc#1173159).
 - CVE-2020-10760: Fix use-after-free in AD DC Global Catalog LDAP
 server with paged_result or VLV, (bso#14402), (1173161).
 - CVE-2020-14303: Fix endless loop from empty UDP packet sent to
 AD DC nbt_server, (bso#14417), (bsc#1173359).
 - CVE-2020-10730: NULL de-reference in AD DC LDAP server when ASQ
 and VLV combined, ldb: Bump version to 1.5.8, (bso#14364),
 (bsc#1173159).
- Update to 4.10.16
 s3: lib: Paranoia around use of snprintf copying into a fixed-size buffer
 from a getenv() pointer.
 lib:util: Fix smbclient -l basename dir, (bso#14345).
 Malicious SMB1 server can crash libsmbclient, (bso#14366).
 s3:libads: Fix ads_get_upn(), (bso#14336).
 docs-xml: Fix usernames in pam_winbind manpages, (bso#14358).
 Client tools are not able to read gencache anymore since 4.10, (bso#14370).
- Update to 4.10.15
 - CVE-2020-10700: Fix use-after-free in AD DC LDAP server when
 ASQ and paged_results combined, (bso#14331), (bsc#1169850).
 - CVE-2020-10704: Fix LDAP Denial of Service (stack overflow) in
 Samba AD DC, (bso#20454), (bsc#1169851).
- Update to 4.10.14
 s3: lib: nmblib. Clean up and harden nmb packet processing, (bso#14239).
 s3: VFS: full_audit. Use system session_info if called from a
 temporary share definition, (bso#14283).
 nmblib: Avoid undefined behaviour in handle_name_ptrs(), (bso#20193).
 dsdb: Correctly handle memory in objectclass_attrs, (bso#14258).
 auth: Fix CID 1458418 Null pointer dereferences (REVERSE_INULL),
 auth: Fix CID 1458420 Null pointer dereferences (REVERSE_INULL), (bso#14247).
 winbind member (source3) fails local SAM auth with empty domain
 name, (bso#14247).
 winbindd: Handling missing idmap in getgrgid(), (bso#14265).
 lib:util: Log mkdir error on correct debug levels, (bso#14253).
 wafsamba: Do not use 'rU' as the 'U' is deprecated in
 Python 3.9, (bso#14266).
 ctdb-tcp: Make error handling for outbound connection
 consistent, (bso#14274).
 Starting ctdb node that was powered off hard before results in
 recovery loop, (bso#14295).
- Update to 4.10.13
 s3: libsmb: Ensure SMB1 cli_qpathinfo2() doesn't return an
 inode number, (bso#14161).
 s3: utils: smbtree. Ensure we don't call cli_RNetShareEnum()
 on an SMB1 connection, (bso#14174).
 s3: libsmb: Ensure return from net_share_enum_rpc() sets
 cli->raw_status on error, (bso#14176).
 s3: smbd: SMB2 - Ensure we use the correct session_id if
 encrypting an interim response, (bso#14189).
 s3: smbd: Only set xconn->smb1.negprot.done = true after
 supported_protocols[protocol].proto_reply_fn() succeeds, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'samba' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"ldb-tools", rpm:"ldb-tools~1.5.8~3.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit", rpm:"libdcerpc-binding0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0", rpm:"libdcerpc-binding0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit", rpm:"libdcerpc0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0", rpm:"libdcerpc0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb1", rpm:"libldb1~1.5.8~3.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb1-32bit", rpm:"libldb1-32bit~1.5.8~3.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit", rpm:"libndr-krb5pac0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0", rpm:"libndr-krb5pac0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit", rpm:"libndr-nbt0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0", rpm:"libndr-nbt0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit", rpm:"libndr-standard0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0", rpm:"libndr-standard0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit", rpm:"libndr0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0", rpm:"libndr0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit", rpm:"libnetapi0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit", rpm:"libsamba-credentials0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0", rpm:"libsamba-credentials0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-32bit", rpm:"libsamba-errors0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0", rpm:"libsamba-errors0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit", rpm:"libsamba-hostconfig0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0", rpm:"libsamba-hostconfig0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-32bit", rpm:"libsamba-passdb0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0", rpm:"libsamba-passdb0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit", rpm:"libsamba-util0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0", rpm:"libsamba-util0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit", rpm:"libsamdb0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0", rpm:"libsamdb0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-32bit", rpm:"libsmbclient0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit", rpm:"libsmbconf0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0", rpm:"libsmbconf0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-32bit", rpm:"libsmbldap2-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2", rpm:"libsmbldap2~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit", rpm:"libtevent-util0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0", rpm:"libtevent-util0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-32bit", rpm:"samba-libs-python3-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.10.17+git.203.862547088ca~3.14.1", rls:"SLES12.0SP5"))) {
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

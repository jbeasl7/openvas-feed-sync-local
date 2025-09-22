# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1635.1");
  script_cve_id("CVE-2017-7508", "CVE-2017-7520", "CVE-2017-7521");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-30 14:28:46 +0000 (Fri, 30 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1635-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1635-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171635-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044947");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-June/002969.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvpn' package(s) announced via the SUSE-SU-2017:1635-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvpn fixes the following issues:

- Some parts of the certificate-parsing code did not always clear all allocated
 memory. This would have allowed clients to leak a few bytes of memory for
 each connection attempt, thereby facilitating a (quite inefficient) DoS
 attack on the server. [bsc#1044947, CVE-2017-7521]

- The ASN1 parsing code contained a bug that could have resulted in some
 buffers being free()d twice, and this issue could have potentially been
 triggered remotely by a VPN peer. [bsc#1044947, CVE-2017-7521]

- If clients used a HTTP proxy with NTLM authentication, a man-in-the-middle
 attacker between client and proxy could cause the client to crash or disclose
 at most 96 bytes of stack memory. The disclosed stack memory was likely to
 contain the proxy password. If the proxy password had not been reused, this
 was unlikely to compromise the security of the OpenVPN tunnel itself. Clients
 who did not use the --http-proxy option with ntlm2 authentication were not
 affected. [bsc#1044947, CVE-2017-7520]

- It was possible to trigger an assertion by sending a malformed IPv6 packet.
 That issue could have been abused to remotely shutdown an openvpn server or
 client, if IPv6 and --mssfix were enabled and if the IPv6 networks used
 inside the VPN were known. [bsc#1044947, CVE-2017-7508]");

  script_tag(name:"affected", value:"'openvpn' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.3.8~16.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-auth-pam-plugin", rpm:"openvpn-auth-pam-plugin~2.3.8~16.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.3.8~16.17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-auth-pam-plugin", rpm:"openvpn-auth-pam-plugin~2.3.8~16.17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.3.8~16.17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn-auth-pam-plugin", rpm:"openvpn-auth-pam-plugin~2.3.8~16.17.1", rls:"SLES12.0SP2"))) {
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

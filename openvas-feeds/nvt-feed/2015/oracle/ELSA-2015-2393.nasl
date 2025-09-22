# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122747");
  script_cve_id("CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713", "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0563", "CVE-2015-0564", "CVE-2015-2188", "CVE-2015-2189", "CVE-2015-2191", "CVE-2015-3182", "CVE-2015-3810", "CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3813", "CVE-2015-6243", "CVE-2015-6244", "CVE-2015-6245", "CVE-2015-6246", "CVE-2015-6248");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:22 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Oracle: Security Advisory (ELSA-2015-2393)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2393");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2393.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the ELSA-2015-2393 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.10.14-7.0.1]
- Add oracle-ocfs2-network.patch to allow disassembly of OCFS2 interconnect

[1.10.14-7]
- Rebase some tvbuff API from upstream to 1.10.14
- Fixes crash when tvb_length_remaining() is used
- Related: CVE-2015-6244

[1.10.14-6]
- Security patch
- Resolves: CVE-2015-3182

[1.10.14-5]
- Fix crash caused by -DGDK_PIXBUF_DEPRECATED on startup
- Resolves: rhbz#1267959

[1.10.14-4]
- Security patches
- Resolves: CVE-2015-6243
 CVE-2015-6244
 CVE-2015-6245
 CVE-2015-6246
 CVE-2015-6248

[1.10.14-3]
- Security patches
- Resolves: CVE-2015-3810
 CVE-2015-3813

[1.10.14-2]
- Add certificate verify message decoding in TLS extension
- Resolves: #1239150

[1.10.14-1]
- Upgrade to 1.10.14
- Resolves: #1238676

[1.10.3-20]
- add master secret extension decoding in TLS extension
- add encrypt-then-mac extension decoding in TLS extension
- Resolves: #1222901

[1.10.3-19]
- create pcap file if -F pcap specified
- Resolves: #1227199

[1.10.3-18]
- add key exchange algorithms decoding in TLS extension
- Resolves: #1222600

[1.10.3-17]
- add signature algorithms decoding in TLS extension
- Resolves: #1221701

[1.10.3-16]
- add relro check
- Resolves: #1092532

[1.10.3-15]
- add elliptic curves decoding in DTLS HELLO
- Resolves: #1131202

[1.10.3-14]
- introduced nanosecond time precision
- Resolves: #1213339

[1.10.3-13]
- security patches
- Resolves: #1148267");

  script_tag(name:"affected", value:"'wireshark' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.10.14~7.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.10.14~7.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.10.14~7.0.1.el7", rls:"OracleLinux7"))) {
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

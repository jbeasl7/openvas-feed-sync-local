# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123057");
  script_cve_id("CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713", "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0564", "CVE-2015-2189", "CVE-2015-2191");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:48 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-1460)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1460");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1460.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the ELSA-2015-1460 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.8.10-17.0.2]
- Fix ocfs2 dissector (John Haxby) [orabug 21505640]

[1.8.10-17.0.1.el6]
- Add oracle-ocfs2-network.patch to allow disassembly of OCFS2 interconnect

[1.8.10-17]
- security patches
- Resolves: CVE-2015-2189
 CVE-2015-2191

[1.8.10-16]
- security patches
- Resolves: CVE-2014-8710
 CVE-2014-8711
 CVE-2014-8712
 CVE-2014-8713
 CVE-2014-8714
 CVE-2015-0562
 CVE-2015-0564

[1.8.10-15]
- fix AES-GCM decoding
- Related: rhbz#1095065

[1.8.10-14]
- fix requires: shadow-utils
- Resolves: rhbz#1121275

[1.8.10-13]
- add elliptic curves decoding in DTLS HELLO
- Resolves: rhbz#1131203

[1.8.10-12]
- add AES-GCM decryption
- Resolves: rhbz#1095065

[1.8.10-11]
- fix reading from pipes
- Resolves: rhbz#1104210

[1.8.10-10]
- introduced nanosecond time precision
- Resolves: rhbz#1146578

[1.8.10-9]
- fix gtk2 required version
- Resolves: rhbz#1160388");

  script_tag(name:"affected", value:"'wireshark' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.10~17.0.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.8.10~17.0.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.8.10~17.0.2.el6", rls:"OracleLinux6"))) {
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

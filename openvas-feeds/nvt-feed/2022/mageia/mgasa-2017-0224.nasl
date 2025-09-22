# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0224");
  script_cve_id("CVE-2017-7508", "CVE-2017-7520", "CVE-2017-7521");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-30 14:28:46 +0000 (Fri, 30 Jun 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0224)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0224");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0224.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21125");
  script_xref(name:"URL", value:"https://community.openvpn.net/openvpn/wiki/VulnerabilitiesFixedInOpenVPN243");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2017-06/msg00027.html");
  script_xref(name:"URL", value:"https://www.ubuntu.com/usn/usn-3339-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvpn' package(s) announced via the MGASA-2017-0224 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was possible to trigger an assertion by sending a malformed IPv6
packet. That issue could have been abused to remotely shutdown an
openvpn server or client, if IPv6 and --mssfix were enabled and if the
IPv6 networks used inside the VPN were known (CVE-2017-7508).

Some parts of the certificate-parsing code did not always clear all
allocated memory. This would have allowed clients to leak a few bytes of
memory for each connection attempt, thereby facilitating a (quite
inefficient) DoS attack on the server (CVE-2017-7521).

If clients used a HTTP proxy with NTLM authentication, a
man-in-the-middle attacker between client and proxy could cause the
client to crash or disclose at most 96 bytes of stack memory. The
disclosed stack memory was likely to contain the proxy password. If the
proxy password had not been reused, this was unlikely to compromise the
security of the OpenVPN tunnel itself. Clients who did not use the
--http-proxy option with ntlm2 authentication were not affected
(CVE-2017-7520).

The ASN1 parsing code contained a bug that could have resulted in some
buffers being free()d twice, and this issue could have potentially been
triggered remotely by a VPN peer (CVE-2017-7521).");

  script_tag(name:"affected", value:"'openvpn' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64openvpn-devel", rpm:"lib64openvpn-devel~2.3.17~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvpn-devel", rpm:"libopenvpn-devel~2.3.17~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.3.17~1.mga5", rls:"MAGEIA5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.98895981899102101");
  script_cve_id("CVE-2025-24356");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-27 02:15:55 +0000 (Wed, 27 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-b895b18cfe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b895b18cfe");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b895b18cfe");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2342133");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2342338");
  script_xref(name:"URL", value:"https://github.com/freifunk-gluon/gluon");
  script_xref(name:"URL", value:"https://github.com/neocturne/fastd/security/advisories/GHSA-pggg-vpfv-4rcv");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fastd' package(s) announced via the FEDORA-2025-b895b18cfe advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This release contains a number of small improvements and bugfixes, including mitigations for the LOW severity vulnerability `CVE-2025-24356`.

## Bugfixes

- Add mitigations for fast-reconnect amplification attacks

 When receiving a data packet from an unknown IP address/port combination, fastd will assume that one of its connected peers has moved to a new address (for example due to internet lines with dynamic IP, or roaming between WWAN and a local internet connection) and initiate a reconnect by sending a handshake packet. This 'fast reconnect' avoids having to wait for a session timeout (up to ~90s) until a new connection is established.

 Even a 1-byte UDP packet just containing the fastd packet type header can trigger a much larger handshake packet (~150 bytes of UDP payload). With fastd v22, this number is doubled, because two handshakes are sent (one in a pre-v22-compatible format and one in a new L2TP-style format). Including IPv4 and UDP headers, the resulting amplification factor is roughly 12-13.

 By sending data packets with a spoofed source address to fastd instances reachable on the internet, this amplification of UDP traffic might be used to facilitate a Distributed Denial of Service attack.

 fastd has always implemented rate limiting for handshakes to unknown IP addresses and ports to 1 handshake per 15s to avoid this kind of attack, however the rate is limited per-port and not per-address, thus still allowing handshakes to be sent to all 65535 UDP ports of the same IP address unlimited.

 The issue has been mitigated in fastd v23 by a number of changes:

 - Rate-limiting has been changed changed to be applied per-address instead of per-port

 - Only one handshake instead of two handshakes is sent for fast-reconnect (by determining from the format of the data packet whether a pre-v22 or L2TP-style handshake should be used)

 - Require at least a full method header instead of just a single byte for a data packet to be considered valid. This does not have an effect on instances that enable the `null` method (regardless of `null` being actually in use), as a single-byte UDP packet is a valid `null` keepalive, but for all other methods the amplification factor is slightly reduced.


 Only fastd instances that allow connections from arbitrary IP addresses are vulnerable. Instances in a 'client' role that configure their peers using the `remote` config option (which includes the common deployment as part of the [Gluon]([link moved to references]) wireless mesh firmware) will not respond to unexpected data packets with a handshake and are therefore unaffected.

 `CVE-2025-24356` has been assigned to this issue. The severity of this vulnerability is considered LOW.

 A GitHub security advisory can be found under [GHSA-pggg-vpfv-4rcv]([link moved to references]).

- Fix config loading to fail on `offload l2tp no,` when L2TP offloading is unsupported by the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'fastd' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"fastd", rpm:"fastd~23~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fastd-debuginfo", rpm:"fastd-debuginfo~23~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fastd-debugsource", rpm:"fastd-debugsource~23~1.fc41", rls:"FC41"))) {
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

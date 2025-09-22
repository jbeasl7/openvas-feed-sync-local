# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4128.1");
  script_cve_id("CVE-2018-17204", "CVE-2018-17205", "CVE-2018-17206");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-29 15:51:44 +0000 (Tue, 29 Jan 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4128-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4128-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184128-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104467");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-December/004965.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvswitch' package(s) announced via the SUSE-SU-2018:4128-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvswitch to version 2.7.6 fixes the following issues:

These security issues were fixed:

- CVE-2018-17205: Prevent OVS crash when reverting old flows in bundle commit
 (bsc#1104467).
- CVE-2018-17206: Avoid buffer overread in BUNDLE action decoding
 (bsc#1104467).
- CVE-2018-17204:When decoding a group mod, it validated the group type and
 command after the whole group mod has been decoded. The OF1.5 decoder, however,
 tried to use the type and command earlier, when it might still be invalid. This
 caused an assertion failure (via OVS_NOT_REACHED) (bsc#1104467).

These non-security issues were fixed:

- ofproto/bond: Fix bond reconfiguration race condition.
- ofproto/bond: Fix bond post recirc rule leak.
- ofproto/bond: fix interal flow leak of tcp-balance bond
- systemd: Restart openvswitch service if a daemon crashes
- conntrack: Fix checks for TCP, UDP, and IPv6 header sizes.
- ofp-actions: Fix translation of set_field for nw_ecn
- netdev-dpdk: Fix mempool segfault.
- ofproto-dpif-upcall: Fix flow setup/delete race.
- learn: Fix memory leak in learn_parse_sepc()
- netdev-dpdk: fix mempool_configure error state
- vswitchd: Add --cleanup option to the 'appctl exit' command
- ofp-parse: Fix memory leak on error path in parse_ofp_group_mod_file().
- actions: Fix memory leak on error path in parse_ct_lb_action().
- dpif-netdev: Fix use-after-free error in reconfigure_datapath().
- bridge: Fix memory leak in bridge_aa_update_trunks().
- dpif-netlink: Fix multiple-free and fd leak on error path.
- ofp-print: Avoid array overread in print_table_instruction_features().
- flow: Fix buffer overread in flow_hash_symmetric_l3l4().
- systemd: start vswitchd after udev
- ofp-util: Check length of buckets in ofputil_pull_ofp15_group_mod().
- ovsdb-types: Fix memory leak on error path.
- tnl-ports: Fix loss of tunneling upon removal of a single tunnel port.
- netdev: check for NULL fields in netdev_get_addrs
- netdev-dpdk: vhost get stats fix.
- netdev-dpdk: use 64-bit arithmetic when converting rates.
- ofp-util: Fix buffer overread in ofputil_decode_bundle_add().
- ofp-util: Fix memory leaks on error cases in ofputil_decode_group_mod().
- ofp-util: Fix memory leaks when parsing OF1.5 group properties.
- ofp-actions: Fix buffer overread in decode_LEARN_specs().
- flow: Fix buffer overread for crafted IPv6 packets.
- ofp-actions: Properly interpret 'output:in_port'.
- ovs-ofctl: Avoid read overrun in ofperr_decode_msg().
- odp-util: Avoid misaligned references to ip6_hdr.
- ofproto-dpif-upcall: Fix action attr iteration.
- ofproto-dpif-upcall: Fix key attr iteration.
- netdev-dpdk: vhost get stats fix.
- netdev-dpdk: use 64-bit arithmetic when converting rates.
- ofp-util: Fix buffer overread in ofputil_decode_bundle_add().
- ofp-util: Fix memory leaks on error cases in ofputil_decode_group_mod().
- ofp-util: Fix memory leaks when parsing OF1.5 group properties.
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openvswitch' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"openvswitch", rpm:"openvswitch~2.7.6~3.23.1", rls:"SLES12.0SP3"))) {
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

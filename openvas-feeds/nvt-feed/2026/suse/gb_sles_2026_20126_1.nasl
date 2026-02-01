# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20126.1");
  script_cve_id("CVE-2025-30219");
  script_tag(name:"creation_date", value:"2026-01-30 04:34:32 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20126-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20126-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620126-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246091");
  script_xref(name:"URL", value:"https://github.com/rabbitmq/rabbitmq-server/releases/tag/v4.0.1");
  script_xref(name:"URL", value:"https://github.com/rabbitmq/rabbitmq-server/releases/tag/v4.1.0");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-January/043747.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rabbitmq-server' package(s) announced via the SUSE-SU-2026:20126-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rabbitmq-server fixes the following issues:

Changes in rabbitmq-server:

Update to 4.1.5:

* Highlights

 - Khepri, an alternative schema data store developed to replace Mnesia,
 has matured and is now fully supported (it previously was an experimental feature)
 - AMQP 1.0 is now a core protocol that is always enabled. Its plugin is now a no-op that only exists to simplify upgrades.
 - The AMQP 1.0 implementation is now significantly more efficient: its peak throughput is more than double than that of 3.13.x
 on some workloads
 - Efficient sub-linear quorum queue recovery on node startup using checkpoints
 - Quorum queues now support priorities (but not exactly the same way as classic queues)
 - AMQP 1.0 clients now can manage topologies similarly to how AMQP 0-9-1 clients do it
 - The AMQP 1.0 convention (address format) used for interacting with with AMQP 0-9-1 entities is now easier to reason about
 - Mirroring (replication) of classic queues was removed after several years of deprecation. For replicated messaging data types,
 use quorum queues and/or streams. Non-replicated classic queues remain and their development continues
 - Classic queue storage efficiency improvements, in particular recovery time and storage of multi-MiB messages
 - Nodes with multiple enabled plugins and little on disk data to recover now start up to 20-30% faster
 - New exchange type: Local Random Exchange
 - Quorum queue log reads are now offloaded to channels (sessions, connections).
 - Initial Support for AMQP 1.0 Filter Expressions
 - Feature Flags Quality of Life Improvements
 - rabbitmqadmin v2

* Breaking Changes

 - Before a client connection can negotiate a maximum frame size (frame_max), it must authenticate
 successfully. Before the authenticated phase, a special lower frame_max value
 is used.
 - With this release, the value was increased from the original 4096 bytes to 8192
 to accommodate larger JWT tokens.
 - amqplib is a popular client library that has been using
 a low frame_max default of 4096. Its users must upgrade to a compatible version
 (starting with 0.10.7) or explicitly use a higher frame_max.
 amqplib versions older than 0.10.7 will not be able to connect to
 RabbitMQ 4.1.0 and later versions due to the initial AMQP 0-9-1 maximum frame size
 increase covered above.
 - The default MQTT Maximum Packet Size changed from 256 MiB to 16 MiB.
 - The following rabbitmq.conf settings are unsupported:

 - cluster_formation.etcd.ssl_options.fail_if_no_peer_cert
 - cluster_formation.etcd.ssl_options.dh
 - cluster_formation.etcd.ssl_options.dhfile

 - Classic Queues is Now a Non-Replicated Queue Type
 - Quorum Queues Now Have a Default Redelivery Limit
 - Up to RabbitMQ 3.13, when an AMQP 0.9.1 client (re-)published a message to RabbitMQ, RabbitMQ interpreted the
 - AMQP 0.9.1 x-death header in the published message's basic_message.content.properties.headers ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'rabbitmq-server' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"erlang-rabbitmq-client", rpm:"erlang-rabbitmq-client~4.1.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rabbitmq-server", rpm:"rabbitmq-server~4.1.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rabbitmq-server-bash-completion", rpm:"rabbitmq-server-bash-completion~4.1.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rabbitmq-server-plugins", rpm:"rabbitmq-server-plugins~4.1.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rabbitmq-server-zsh-completion", rpm:"rabbitmq-server-zsh-completion~4.1.5~160000.1.1", rls:"SLES16.0.0"))) {
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

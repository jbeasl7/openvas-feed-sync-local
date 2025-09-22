# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884789");
  script_cve_id("CVE-2023-0809", "CVE-2023-28366", "CVE-2023-3592");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:18 +0000 (Sat, 16 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-04 17:00:37 +0000 (Wed, 04 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-9adc4be8b0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-9adc4be8b0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-9adc4be8b0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mosquitto' package(s) announced via the FEDORA-2023-9adc4be8b0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"2.0.17

Broker:

* Fix `max_queued_messages 0` stopping clients from receiving messages
* Fix `max_inflight_messages` not being set correctly.

Apps:

* Fix `mosquitto_passwd -U` backup file creation.


2.0.16

Security:

* CVE-2023-28366: Fix memory leak in broker when clients send multiple QoS 2 messages with the same message ID, but then never respond to the PUBREC commands.
* CVE-2023-0809: Fix excessive memory being allocated based on malicious initial packets that are not CONNECT packets.
* CVE-2023-3592: Fix memory leak when clients send v5 CONNECT packets with a will message that contains invalid property types.
* Broker will now reject Will messages that attempt to publish to $CONTROL/.
* Broker now validates usernames provided in a TLS certificate or TLS-PSK identity are valid UTF-8.
* Fix potential crash when loading invalid persistence file.
* Library will no longer allow single level wildcard certificates, e.g. *.com

Broker:

* Fix $SYS messages being expired after 60 seconds and hence unchanged values disappearing.
* Fix some retained topic memory not being cleared immediately after used.
* Fix error handling related to the `bind_interface` option.
* Fix std* files not being redirected when daemonising, when built with assertions removed.
* Fix default settings incorrectly allowing TLS v1.1.
* Use line buffered mode for stdout. Closes #2354.
* Fix bridges with non-matching cleansession/local_cleansession being expired on start after restoring from persistence.
* Fix connections being limited to 2048 on Windows. The limit is now 8192, where supported.
* Broker will log warnings if sensitive files are world readable/writable, or if the owner/group is not the same as the user/group the broker is running as. In future versions the broker will refuse to open these files.
* mosquitto_memcmp_const is now more constant time.
* Only register with DLT if DLT logging is enabled.
* Fix any possible case where a json string might be incorrectly loaded. This could have caused a crash if a textname or textdescription field of a role was not a string, when loading the dynsec config from file only.
* Dynsec plugin will not allow duplicate clients/groups/roles when loading config from file, which matches the behaviour for when creating them.
* Fix heap overflow when reading corrupt config with 'log_dest file'.

Client library:

* Use CLOCK_BOOTTIME when available, to keep track of time. This solves the problem of the client OS sleeping and the client hence not being able to calculate the actual time for keepalive purposes.
* Fix default settings incorrectly allowing TLS v1.1.
* Fix high CPU use on slow TLS connect.

Clients:

* Fix incorrect topic-alias property value in mosquitto_sub json output.
* Fix confusing message on TLS certificate verification.

Apps:

* mosquitto_passwd uses mkstemp() for backup files.
* `mosquitto_ctrl dynsec init` will refuse to overwrite an existing file, without a race-condition.");

  script_tag(name:"affected", value:"'mosquitto' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"mosquitto", rpm:"mosquitto~2.0.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mosquitto-debuginfo", rpm:"mosquitto-debuginfo~2.0.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mosquitto-debugsource", rpm:"mosquitto-debugsource~2.0.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mosquitto-devel", rpm:"mosquitto-devel~2.0.17~1.fc39", rls:"FC39"))) {
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

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.9910210104996093");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-cfe04c6093)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-cfe04c6093");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-cfe04c6093");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252372");
  script_xref(name:"URL", value:"https://www.unrealircd.org/central-api/");
  script_xref(name:"URL", value:"https://www.unrealircd.org/docs/Central_Blocklist");
  script_xref(name:"URL", value:"https://www.unrealircd.org/docs/Central_Spamfilter");
  script_xref(name:"URL", value:"https://www.unrealircd.org/docs/Central_spamreport");
  script_xref(name:"URL", value:"https://www.unrealircd.org/docs/Deny_channel_block");
  script_xref(name:"URL", value:"https://www.unrealircd.org/docs/Dev:URL_API");
  script_xref(name:"URL", value:"https://www.unrealircd.org/docs/Listen_block#options_block_");
  script_xref(name:"URL", value:"https://www.unrealircd.org/docs/Proxy_block");
  script_xref(name:"URL", value:"https://www.unrealircd.org/docs/Set_block#set::hide-ban-reason");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unrealircd' package(s) announced via the FEDORA-2023-cfe04c6093 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# UnrealIRCd 6.1.3

The main focus of this release is adding countermeasures against large scale spam/drones. Upstream does this by offering a central API which can be used for accessing Central Blocklist, Central Spamreport and Central Spamfilter.

## Enhancements
 * Central anti-spam services:
 * The services from below require a central-api key, which you can [request here]([link moved to references]).
 * [Central Blocklist]([link moved to references]) is an attempt to detect and block spammers. It works similar to DNS Blacklists but the central blocklist receives many more details about the user that is trying to connect and therefore can make a better decision on whether a user is likely a spammer.
 * [Central Spamreport]([link moved to references]) allows you to send spam reports (user details, last sent lines) via the `SPAMREPORT` command. This information may then be used to improve [Central Blocklist]([link moved to references]) and/or [Central Spamfilter]([link moved to references]).
 * The [Central Spamfilter]([link moved to references]), which provides `spamfilter { }` blocks that are centrally managed, is now fetched from a different URL if you have an Central API key set. This way, upstream can later provide `spamfilter { }` blocks that build on central blocklist scoring functionality, and also so upstream doesn't have to reveal all the central spamfilter blocks to the world.
 * New option `auto` for [set::hide-ban-reason]([link moved to references]), which is now the default. This will hide the \*LINE reason to other users if the \*LINE reason contains the IP of the user, for example when it contains a DroneBL URL which has `lookup?ip=XXX`. This to protect the privacy of the user. Other possible settings are `no` (never hide, the previous default) and `yes` to always hide the \*LINE reason. In all cases the user affected by the server ban can still see the reason and IRCOps too.
 * Make [Deny channel]([link moved to references]) support escaped sequences like `channel '#xyz\*',` so you can match a literal `*` or `?` via `\*` and `\?`.
 * New option [listen::options::websocket::allow-origin]([link moved to references](optional)): this allows to restrict websocket connections to a list of websites (the sites hosting the HTML/JS page that makes the websocket connection). It doesn't *securely* restrict it though, non-browsers will bypass this restriction, but it can still be useful to restrict regular webchat users.
 * The [Proxy block]([link moved to references]) already had support for reverse proxying with the `Forwarded` header. Now it also properly supports `X-Forwarded-For`. If you previously used a proxy block with type `web`, then you now need to choose one of the new types explicitly. Note that using a reverse proxy for IRC traffic is rare (see the proxy block docs for details), but upstream offers the option.

## Changes
 * Reserve more file ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'unrealircd' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"unrealircd", rpm:"unrealircd~6.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrealircd-debuginfo", rpm:"unrealircd-debuginfo~6.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrealircd-debugsource", rpm:"unrealircd-debugsource~6.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrealircd-maxmind", rpm:"unrealircd-maxmind~6.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrealircd-maxmind-debuginfo", rpm:"unrealircd-maxmind-debuginfo~6.1.3~1.fc39", rls:"FC39"))) {
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

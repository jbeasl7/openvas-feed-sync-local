# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808093");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-06-21 12:44:48 +0530 (Tue, 21 Jun 2016)");
  script_name("Elasticsearch Logstash Version Detection");

  script_tag(name:"summary", value:"Check for the version of Elasticsearch
  Logstash.

  This script sends an HTTP GET request and tries to get the version of
  Elasticsearch Logstash from the response.

  This VT has been deprecated and merged into the VT 'Elasticsearch and Logstash Detection'
  (OID: 1.3.6.1.4.1.25623.1.0.105031)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

# This had only detected Elasticsearch and assumed that "Logstash" is installed.
# However port 9200 is the Elasticsearch service and the version gathering method
# previously used just gathered the Elasticsearch version once a "logstash" index
# was available.
exit(66);

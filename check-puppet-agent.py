#!/usr/bin/python
#
# Check puppet agents for problems.  Looks for failed runs, disabled agents, readonly filesystems,
# stale puppet locks, and existence in Foreman/class in foreman.
#
# Relies on pssh to populate a directory (base_path) with files formatted as follows:
# 
#run_status:[0|1..]
#agent_disabled:[0|1]
#[list of RO mounts|noro]
#[locked|nolock]
#
#ie:
#failed:1
#disabled:1
#noro
#locked
#
# filenames in "base_path" should be IP addresses.

from foreman.client import Foreman
import os
import socket
import csv
import requests
import time
requests.packages.urllib3.disable_warnings()


# pssh
# pssh -p 40 -h hosts -l <username> -o pssh5 -A 'set -o pipefail; grep failed: /var/lib/puppet/state/last_run_summary.yaml 2>/dev/null | tr -d " " || echo nofail; test -e /var/lib/puppet/state/agent_disabled.lock; echo disabled:$?; grep ro, /proc/mounts | grep -v /proc | grep -v /dev/loop | grep -v /sys | grep -v nfs | tr "\n" ":" && echo || echo noro; found=$(find /var/lib/puppet/state -name agent_catalog_run.lock -mmin +240); ( test -z $found && echo nolock ) || echo locked; uname -n'

# clean files
# sed -i -e '/^Unable to create\.*/d' -e '/^Creating directory.*/d' *

f = open("failed_splunk_upgrades.csv", 'wt')
writer = csv.writer(f)
writer.writerow(("Hostname", "IP Address", "Hostgroup", "Last Puppet Run", "Puppet Status", "Stuck Puppet", "Foreman Status", "Splunk::Forwarder", "Comments"))

base_path = "pssh6/"
puppet_class = "splunk::forwarder"

# Foreman is throwing 500 errors sometimes, so adding a retry...
def call_foreman(foreman, function, params):
  f = getattr(foreman, function)
  notdone = True
  counter = 0
  count = 10
  while notdone:
    try:
      if params:
        val = f(**params)
      else:
        val = f()
      notdone = False
    except:
      time.sleep(1)
      notdone = True
      counter += 1
      if counter >= 10:
        val = "foreman unresponsive"
        break
  return val


# Check Foreman return values
def check_values(h):

  if h.get("subtotal") == 1:
    h_id = h.get("results")[0]['hostgroup_id']
    hg = call_foreman(foreman, "show_hostgroups", {"id": h_id})
    if hg:
      base_group = hg['title']
    else:
      base_group = "None"

    foreman_status = "found"
    retry = False

  elif h.get("subtotal") > 1:
    base_group = ""
    foreman_status = "more than one host found"
    retry = False
  else:
    base_group = "not found"
    foreman_status = "not found"
    retry = True

  return retry, base_group, foreman_status
  
# get foreman info.  first try to look up by IP, then by DNS name, and finally use name from host.
foreman = Foreman(os.environ['foreman_host'], (os.environ['foreman_user'], os.environ['foreman_password']), api_version="2")

for ip in os.listdir(base_path):
  # get hostname
  try:
    hostname = socket.gethostbyaddr(ip)
    hostname = hostname[0]
  except socket.herror:
    hostname = ""

  # get puppet info
  if os.stat("%s/%s" % (base_path, ip,)).st_size == 0:
    puppet_run = puppet_status = stuck_puppet = "login failed"
    ro_mounts = ""
    local_hostname = ""
  else:
    with open("%s/%s" % (base_path, ip,)) as f2:
      run_status, agent_disabled, ro_mounts, stuck_puppet, local_hostname  = f2.read().strip().split("\n")
      print ip, local_hostname

      if run_status.startswith("nofail"):
         puppet_run = ""
      else:
         puppet_run = run_status.split(":")[1]

      agent_disabled = agent_disabled.split(":")[1]
      puppet_status = "disabled" if agent_disabled == 0 else "enabled"

      stuck_puppet = True if stuck_puppet.startswith("locked") else False


  # try IP
  h = call_foreman(foreman, "index_hosts", {"search": "ip=%s" % ip})
  retry, base_group, foreman_status = check_values(h)

  if retry: 
    if hostname:
      # try DNS hostname
      h = call_foreman(foreman, "index_hosts", {"search": "name=%s" % hostname})
      retry, base_group, foreman_status = check_values(h)
      foreman_status += " (used dns name)"
    else:
      if local_hostname:
        # try local hostname
        h = call_foreman(foreman, "index_hosts", {"search": "name=%s" % local_hostname})
        retry, base_group, foreman_status = check_values(h)
        foreman_status += " (used local hostname)"
        hostname = local_hostname
  else:
    foreman_status += " (used ip)"


  #if h.get("subtotal") == 1:
  #  h_id = h.get("results")[0]['hostgroup_id']
  #  hg = call_foreman(foreman, "show_hostgroups", {"id": h_id})
  #  if hg:
  #    base_group = hg['title']
  #  else:
  #    base_group = "None"

  #  foreman_status = "found"

  #elif h.get("subtotal") > 1:
  #  base_group = ""
  #  foreman_status = "more than one host found"
  #else:

  #  h = call_foreman(foreman, "index_hosts", {"search": "name=%s" % hostname})
  #  if h.get("subtotal") == 1:
  #    h_id = h.get("results")[0]['hostgroup_id']
  #    hg = call_foreman(foreman, "show_hostgroups", {"id": h_id})
  #    if hg:
  #      base_group = hg['title']
  #    else:
  #      base_group = "None"
  #  elif h.get("subtotal") > 1:
  #    base_group = ""
  #    foreman_status = "more than one host found (by name)"
  #  else:
  #    base_group = ""
  #    foreman_status = "host not found (by name)"

  # If there's a base group, see if it has the correct class
  if base_group != "None":
    # Is there a parent class?
    if base_group.find("/") != -1:
       groups = base_group.split("/")
    else:
       groups = [base_group]

    # Get all hostgroups with our class and put them in a list
    hg = call_foreman(foreman, "index_hostgroups", {"search": "class={0}".format(puppet_class)})
    if hg['subtotal'] > hg['per_page']: print "***DID NOT RETRIEVE ALL PAGES***"
    hg_titles = [ hostgroup['title'] for hostgroup in hg['results'] ]

    # see if our hostgroup has the class
    sf_class_flag = False
    for group in groups:
      if group in hg_titles:
        sf_class_flag = True

    # check for inheritance
    if not sf_class_flag:
      while True:
        parent = "/".join(base_group.split("/")[:-1])
        if parent:
          if parent in hg_titles:
            sf_class_flag = True
            break
        else:
          break
        if parent.find("/") == -1:
          break

  writer.writerow((hostname, ip, base_group, puppet_run, puppet_status, stuck_puppet, foreman_status, sf_class_flag, "" if ro_mounts == "noro" else ro_mounts))

f.close()


